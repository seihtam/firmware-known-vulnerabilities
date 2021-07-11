import os
import sys
import subprocess
import sqlite3
import json
import argparse
from collections import namedtuple

# Connect to database
db_conn = sqlite3.connect("database.db")
db = db_conn.cursor()

# Setup database
db.executescript("""
CREATE TABLE IF NOT EXISTS vendor (
	id INTEGER PRIMARY KEY,
	name TEXT UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS product (
	id INTEGER PRIMARY KEY,
	vendor_id INTEGER NOT NULL,
	name TEXT UNIQUE NOT NULL,
	FOREIGN KEY(vendor_id) REFERENCES vendor(id)
);

CREATE TABLE IF NOT EXISTS firmware (
	id INTEGER PRIMARY KEY,
	path TEXT UNIQUE NOT NULL,
	extracted_path TEXT UNIQUE,
	version TEXT,
	build TEXT,
	release_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS firmware_product (
	id INTEGER PRIMARY KEY,
	firmware_id INTEGER NOT NULL,
	product_id INTEGER NOT NULL,
	FOREIGN KEY(firmware_id) REFERENCES firmware(id),
	FOREIGN KEY(product_id) REFERENCES product(id),
	UNIQUE(firmware_id, product_id)
);

CREATE TABLE IF NOT EXISTS program (
	id INTEGER PRIMARY KEY,
	name TEXT UNIQUE NOT NULL,
	version_regex TEXT NOT NULL,
	cpe TEXT NOT NULL,
	filename TEXT
);

CREATE TABLE IF NOT EXISTS program_version (
	id INTEGER PRIMARY KEY,
	program_id INTEGER NOT NULL,
	version TEXT NOT NULL,
	FOREIGN KEY(program_id) REFERENCES program(id)
);

CREATE TABLE IF NOT EXISTS cve (
	id INTEGER PRIMARY KEY,
	name TEXT UNIQUE NOT NULL,
	description TEXT,
	cvss2 INTEGER,
	cvss3 INTEGER,
	published_date TEXT
);

CREATE TABLE IF NOT EXISTS cve_program_version (
	id INTEGER PRIMARY KEY,
	cve_id INTEGER NOT NULL,
	program_version_id INTEGER NOT NULL,
	FOREIGN KEY(cve_id) REFERENCES cve(id),
	FOREIGN KEY(program_version_id) REFERENCES program_version(id),
	UNIQUE(cve_id, program_version_id)
);

CREATE TABLE IF NOT EXISTS firmware_program_version (
	id INTEGER PRIMARY KEY,
	firmware_id INTEGER NOT NULL,
	program_version_id INTEGER NOT NULL,
	FOREIGN KEY(firmware_id) REFERENCES firmware(id),
	FOREIGN KEY(program_version_id) REFERENCES program_version(id),
	UNIQUE(firmware_id, program_version_id)
);
""")

# SETTINGS
program_information = [
	("BusyBox", "BusyBox v\\d\\.\\d+\\.*\\d*", "cpe:/a:busybox:busybox:"),
	("wpa_supplicant", "wpa_supplicant v\\d.\\d\\.*\\d*", "cpe:/a:w1.fi:wpa_supplicant:"),
	("OpenSSL", "OpenSSL \\d\\.\\d\\.\\d[a-z]*", "cpe:/a:openssl:openssl:"),
	("cURL", "curl \\d\\.\\d+\\.\\d", "cpe:/a:haxx:curl:"),
	("dnsmasq", "dnsmasq-\\d\\.\\d+", "cpe:/a:thekelleys:dnsmasq:"),
	("vsFTPd", "vsFTPd \\d.\\d.\\d+", "cpe:/a:vsftpd_project:vsftpd:"),
	("Dropbear", "dropbear_\\d\\d\\d\\d\\.\\d\\d", "cpe:/a:dropbear_ssh_project:dropbear_ssh:")
]

unpack_timeout_path = "D:\\timeout"

unpack_failed_path = "D:\\failed"

# Insert programs in database
for p in program_information:
	if not db.execute("SELECT id FROM program WHERE name = ?", (p[0],)).fetchone():
		db.execute("INSERT INTO program (name, version_regex, cpe) VALUES (?,?,?)", p)
db_conn.commit()

# Extract list of programs from database
# The reason we insert the programs in the database and then extract them, is that we need a database id for each program to make references to
programs = []
program_tuple = namedtuple('program', ['id', 'name', 'version_regex', 'cpe', 'filename'])
for p in db.execute("SELECT id, name, version_regex, cpe, filename FROM program").fetchall():
	programs.append(program_tuple(p[0], p[1], p[2], p[3], p[4]))


def extract_firmware(path):
	folder, filename = os.path.split(path)

	# Check if firmware is already extracted
	# binwalk's --directory parameter seems to be ignored, so can't specify output folder, but this is the default
	output_folder = os.path.join(folder, "_" + filename + ".extracted")
	if os.path.exists(output_folder):
		return output_folder

	# Use binwalk to extract firmware
	# https://github.com/ReFirmLabs/binwalk
	try:
		subprocess.check_output('docker run --rm -v "{}:/binwalk" rjocoleman/binwalk -Me -d 20 "{}"'.format(
			os.path.abspath(folder),  # docker needs the absolute path, relative path doesn't work
			filename
		), timeout=180)
	except subprocess.TimeoutExpired:
		# Kill docker process
		os.system('FOR /f "tokens=*" %i IN (\'docker ps -q\') DO docker stop %i')
		if os.path.exists(output_folder):
			os.system('move {} {}'.format(output_folder, unpack_timeout_path))
		return None
	except subprocess.CalledProcessError as e:
		with open("errors.txt", "a") as f:
			f.write(str(e))
			f.write("\n")
		return None

	# Check if output folder exists after extraction
	if not os.path.exists(output_folder):
		return None

	# Check if firmware filesystem have been extracted
	common_files_and_folders = {'bin', 'etc', 'dev', 'lib', 'opt', 'proc', 'sys', 'tmp', 'usr', 'mnt', 'var'}
	extracted_correctly = False
	for root, dirs, files in os.walk(output_folder, onerror=print):
		# Check if any dictionaries in the common list
		if any(dir in common_files_and_folders for dir in dirs):
			extracted_correctly = True
			break
		# Check if any files in the common list
		if any(filename in common_files_and_folders for filename in files):
			extracted_correctly = True
			break

	# If firmware filesystem have not been extracted correctly then delete folder and return none
	if not extracted_correctly:
		if os.path.exists(output_folder):
			os.system('move {} {}'.format(output_folder, unpack_failed_path))
		return None

	return output_folder


def find_programs(path, firmware_id):
	# Using ripgrep to search for regex patterns
	# https://github.com/BurntSushi/ripgrep
	# --text: Search binary files as if they were text
	# --no-messages: Suppress all error messages related to opening and reading files
	# --no-line-number: Suppress line numbers
	# --hidden: Search hidden files and directories
	# --no-ignore: Don't respect ignore files (.gitignore, .ignore, etc.)
	# --only-matching: Print only the matched (non-empty) parts of a matching line
	# --with-filename: Display the file path for matches
	# --regexp: Regex pattern
	# Note: it would be more efficient to load all regexes into a single command, but there is no good way to tell which regex matched then
	for program in programs:
		try:
			output = subprocess.check_output('rg --text --no-messages --no-line-number --hidden --no-ignore --only-matching --with-filename --regexp "{}" "{}"'.format(program.version_regex, path), encoding="utf8")
		except subprocess.CalledProcessError as e:
			# ripgrep will fail with error code 2 if files were encountered that could not be opened,
			# this is expected in our case because of special filesystem files in the extracted firmware,
			# if there actually is an error (stderr not empty) then raise the error
			if e.stderr:
				raise e
			else:
				output = e.stdout

		# Parse found program version strings from command output
		# Example output: C:\path\to\hostapd:hostapd v0.5.9
		for line in output.splitlines():
			_, filename_and_match = os.path.split(line)
			filename, match = filename_and_match.split(":", 1)

			# If program requires a specific filename then check if it's correct
			if program.filename and program.filename != filename:
				continue

			# Extract program version
			if " " in match:
				_, program_version = match.split(" ", 1)
			elif "-" in match:
				_, program_version = match.split("-", 1)
			else:
				_, program_version = match.split("_", 1)

			if " " in program_version:
				raise Exception("Did not expect to find space in {} for program {}".format(match, program))

			# Insert result in database
			program_version_id = db.execute("SELECT id FROM program_version WHERE program_id = ? AND version = ?", (program.id, program_version,)).fetchone()
			if not program_version_id:
				db.execute("INSERT INTO program_version (program_id, version) VALUES (?,?)", (program.id, program_version,))
				program_version_id = db.lastrowid
			else:
				program_version_id = program_version_id[0]

			if not db.execute("SELECT id FROM firmware_program_version WHERE firmware_id = ? AND program_version_id = ?", (firmware_id, program_version_id,)).fetchone():
				db.execute("INSERT INTO firmware_program_version (firmware_id, program_version_id) VALUES (?,?)", (firmware_id, program_version_id,))


def cve_lookup():
	providers = os.listdir("nvdcve")
	provider_paths = [os.path.join("nvdcve", provider) for provider in providers]

	# Load CVE data files into memory so we can lookup data about CVE's
	cve = namedtuple('cve', ['description', 'cvss2', 'cvss3', 'published_date'])
	cve_details = dict()

	for provider in provider_paths:
		with open(provider, 'r', encoding='utf-8') as f:
			cve_data = json.load(f)
			for c in cve_data["CVE_Items"]:
				cve_name = c["cve"]["CVE_data_meta"]["ID"]
				cve_description = None
				cve_cvss2 = None
				cve_cvss3 = None
				cve_published_date = c["publishedDate"]

				for description in c["cve"]["description"]["description_data"]:
					if description["lang"] == "en":
						cve_description = description["value"]
				if "baseMetricV2" in c["impact"]:
					cve_cvss2 = c["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
				if "baseMetricV3" in c["impact"]:
					cve_cvss3 = c["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]

				cve_details[cve_name] = cve(cve_description, cve_cvss2, cve_cvss3, cve_published_date)

	# Create CPE strings by combining cpe with program version
	cpe_strings = dict()
	for cpe in db.execute("SELECT program_version.id, program.cpe, program_version.version FROM program JOIN program_version ON program.id = program_version.program_id").fetchall():
		cpe_strings[cpe[1]+cpe[2]] = cpe[0]

	# Run cpe2cve program to get CVE's associated with CPE
	for line in subprocess.check_output("cpe2cve -cpe 1 -e 1 -cve 2 -matches 1 {}".format(" ".join(provider_paths)), encoding="utf8", input=",".join(cpe_strings.keys())).splitlines():
		# Extract CPE's and CVE
		cpes, cve_name = line.split("\t", 1)

		# We might get multiple CPE's that's related to the same CVE
		for cpe in cpes.split(","):
			# Lookup program version id from CPE
			program_version_id = cpe_strings[cpe]

			# Insert CVE in database
			cve_id = db.execute("SELECT id FROM cve WHERE name = ?", (cve_name,)).fetchone()
			if not cve_id:
				# Lookup extra information about CVE
				cd = cve_details[cve_name]

				db.execute("INSERT INTO cve (name, description, cvss2, cvss3, published_date) VALUES (?, ?, ?, ?, ?)", (cve_name, cd.description, cd.cvss2, cd.cvss3, cd.published_date,))
				cve_id = db.lastrowid
			else:
				cve_id = cve_id[0]

			# Link CVE and program version in database
			if not db.execute("SELECT id FROM cve_program_version WHERE cve_id = ? and program_version_id = ?", (cve_id, program_version_id,)).fetchone():
				db.execute("INSERT INTO cve_program_version (cve_id, program_version_id) VALUES (?,?)", (cve_id, program_version_id,))


parser = argparse.ArgumentParser(description='Find known vulnerable software in firmware files.')
parser.add_argument('-i', '--import-scraper', help='import firmware information from given scraper database file')
parser.add_argument('-u', '--unpack', help='attempt unpack all firmware that is imported and exists in the given folder')
parser.add_argument('-p', '--programs', help='find programs in unpacked firmware in the given folder and lookup vulnerabilities', action='store_true')
args = parser.parse_args()

if not args.import_scraper and not args.unpack and not args.programs:
	parser.error("At least one argument is required")

if args.import_scraper:
	print("Importing data from scraper database...")
	if not os.path.exists(args.import_scraper):
		raise Exception("Scraper database file specified doesn't exist")

	# Import data from scraper database
	scraper_db_conn = sqlite3.connect(args.import_scraper)
	scraper_db = scraper_db_conn.cursor()

	scraper_data = scraper_db.execute("""
	SELECT brand.name, product.product, image.filename, product.version, product.build, product.date
	FROM image
	JOIN brand ON brand.id = image.brand_id
	JOIN product ON product.iid = image.id
	""").fetchall()

	for data in scraper_data:
		vendor_name = data[0]
		product_name = data[1]
		firmware_path = data[2]
		firmware_version = data[3]
		firmware_build = data[4]
		firmware_release_date = data[5]
		if not vendor_name or not product_name or not firmware_path or not firmware_release_date:
			raise Exception("Data from scraper database doesn't include all necessary information: {}".format(data))

		# Insert vendor in database if not exists
		vendor_id = db.execute("SELECT id FROM vendor WHERE name=?", (vendor_name,)).fetchone()
		if not vendor_id:
			db.execute("INSERT INTO vendor(name) VALUES(?)", (vendor_name,))
			vendor_id = db.lastrowid
		else:
			vendor_id = vendor_id[0]

		# Insert product in database if not exists
		product_id = db.execute("SELECT id FROM product WHERE name=?", (product_name,)).fetchone()
		if not product_id:
			db.execute("INSERT INTO product(vendor_id, name) VALUES(?,?)", (vendor_id, product_name,))
			product_id = db.lastrowid
		else:
			product_id = product_id[0]

		# Check if firmware already exists in database
		# Sometimes different products use the same firmware
		firmware_id = db.execute("SELECT id FROM firmware WHERE path=?", (firmware_path,)).fetchone()
		if not firmware_id:
			# Insert firmware in database
			db.execute("INSERT INTO firmware(path, version, build, release_date) VALUES(?,?,?,?)", (firmware_path, firmware_version, firmware_build, firmware_release_date,))
			firmware_id = db.lastrowid
		else:
			firmware_id = firmware_id[0]

		# Link firmware with product
		firmware_product_id = db.execute("SELECT id FROM firmware_product WHERE firmware_id=? AND product_id=?", (firmware_id, product_id,)).fetchone()
		if not firmware_product_id:
			db.execute("INSERT INTO firmware_product(firmware_id, product_id) VALUES(?,?)", (firmware_id, product_id,))

	db_conn.commit()
	scraper_db_conn.close()

if args.unpack:
	# Generate list of firmware files to unpack
	firmware_files = []
	for firmware_id, path in db.execute("SELECT id, path FROM firmware WHERE extracted_path IS NULL").fetchall():
		firmware_files.append((firmware_id, os.path.join(args.unpack, path)))
	if len(firmware_files) == 0:
		print("No imported firmware to unpack, either nothing is imported or they are already unpacked")

	# Attempt to unpack firmware
	for index, (firmware_id, path) in enumerate(firmware_files):
		print("Unpacking firmware {}/{}".format(index+1, len(firmware_files)))

		# Attempt to extract firmware
		extracted_path = extract_firmware(path)

		if extracted_path:
			# Mark firmware as extracted
			db.execute("UPDATE firmware SET extracted_path = ? WHERE id=?", (extracted_path, firmware_id,))

		db_conn.commit()

if args.programs:
	# Generate list of unpacked firmware to analyse
	unpacked_firmware = []
	for firmware_id, extract_path in db.execute("SELECT id, extracted_path FROM firmware WHERE extracted_path IS NOT NULL").fetchall():
		unpacked_firmware.append((firmware_id, extract_path))
	if len(unpacked_firmware) == 0:
		print("No unpacked firmware to extract programs from")

	# Extract programs
	for index, (firmware_id, extracted_path) in enumerate(unpacked_firmware):
		print("Finding programs in firmware {}/{}: {}".format(index + 1, len(unpacked_firmware), extracted_path))

		# Find program version strings
		find_programs(extracted_path, firmware_id)

		db_conn.commit()

	# Find vulnerable programs
	cve_lookup()
	db_conn.commit()


# Close database connection
db_conn.commit()
db_conn.close()
