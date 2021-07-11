import os
import sys
import json
import magic # https://github.com/ahupp/python-magic
from collections import Counter

filenames = []
filenames_executable = []
filenames_sharedlib = []
filenames_shellscript = []
filenames_object = []
magic_id = []
magic_mime = []

failed_stat_count = 0
failed_libmagic_count = 0
empty_count = 0

progress_display_counter = 1

for root, dirs, files in os.walk(sys.argv[1], onerror=print):
    filenames.extend(files)

    if len(filenames) > progress_display_counter * 10000:
        print("Progress: {}".format(len(filenames)))
        progress_display_counter += 1

    for filename in files:
        path = os.path.join(root, filename)
        try:
            size = os.stat(path).st_size
            if size == 0:
                empty_count += 1
                continue
        except OSError:
            failed_stat_count += 1
            continue

        try:
            magic_id.append(magic.from_file(path))
            mime = magic.from_file(path, mime=True)
            magic_mime.append(mime)

            if mime == 'application/x-executable':
                filenames_executable.append(filename)
            elif mime == 'application/x-sharedlib':
                # Shared libraries often contain version number in their filename, remove that before adding to list
                filenames_sharedlib.append(filename.split('.so')[0])
            elif mime == 'text/x-shellscript':
                filenames_shellscript.append(filename)
            elif mime == 'application/x-object':
                filenames_object.append(filename)

        except magic.magic.MagicException as e:
            print("{}: {}".format(path, e))
            failed_libmagic_count += 1

filenames_count = Counter(filenames)
filenames_executable_count = Counter(filenames_executable)
filenames_sharedlib_count = Counter(filenames_sharedlib)
filenames_shellscript_count = Counter(filenames_shellscript)
filenames_object_count = Counter(filenames_object)
magic_id_count = Counter(magic_id)
magic_mime_count = Counter(magic_mime)

with open('filenames.txt', 'w') as f:
    f.write(json.dumps(filenames_count))
with open('filenames_executable.txt', 'w') as f:
    f.write(json.dumps(filenames_executable_count))
with open('filenames_sharedlib.txt', 'w') as f:
    f.write(json.dumps(filenames_sharedlib_count))
with open('filenames_shellscript.txt', 'w') as f:
    f.write(json.dumps(filenames_shellscript_count))
with open('filenames_object.txt', 'w') as f:
    f.write(json.dumps(filenames_object_count))
with open('magic_id.txt', 'w') as f:
    f.write(json.dumps(magic_id_count))
with open('magic_mime.txt', 'w') as f:
    f.write(json.dumps(magic_mime_count))

print(filenames_count.most_common(100))
print()
print(filenames_executable_count.most_common(100))
print()
print(filenames_sharedlib_count.most_common(100))
print()
print(filenames_shellscript_count.most_common(100))
print()
print(filenames_object_count.most_common(100))
print()
print(magic_id_count.most_common(100))
print()
print(magic_mime_count.most_common(100))
print()

print("Failed stat: {}".format(failed_stat_count))
print("Empty: {}".format(empty_count))
print("Failed libmagic: {}".format(failed_libmagic_count))
