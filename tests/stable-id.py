#!/usr/bin/env python

import sys
import pickle

def allocate_id(ids, id, strict):
    if strict:
        if id in ids and ids[id] == id:
            return
        elif id not in ids.values():
            ids[id] = id;
        else:
            sys.stderr.write("Couldn't assign requested id\n")
            sys.exit(1)

    if id in ids:
        return

    # Allocate the lowest available id
    for i in range(1, 1000):
        if str(i) not in ids.values():
            ids[id] = str(i)
            return

    sys.stderr.write("Couldn't allocate stable id\n")
    sys.exit(1)

if __name__ == '__main__':
    strict = False
    delete = False

    if len(sys.argv) == 3 and sys.argv[2] == "--strict":
        strict = True
    elif len(sys.argv) == 3 and sys.argv[2] == "--del":
        delete = True
    elif len(sys.argv) != 2:
        sys.stderr.write("%s <file> [--strict|--del]\n" % sys.argv[0])
        sys.exit(1)

    try:
        f = open(sys.argv[1], 'rb')
        ids = pickle.load(f)
        f.close()
    except IOError:
        ids = {}

    id = sys.stdin.readline().strip()

    if delete:
        if id in ids:
            del ids[id]
    else:
        allocate_id(ids, id, strict)
        print ids[id]

    f = open(sys.argv[1], 'wb')
    pickle.dump(ids, f, pickle.HIGHEST_PROTOCOL)
    f.close()
