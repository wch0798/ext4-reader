# SD Card Repair
Decky Loader plugin for removable EXT2/3/4 storage. It unmounts the selected filesystem, runs e2fsck -f -p, and remounts it. System mountpoints are excluded.

Repair mode: root backend, `e2fsck -f -y`, followed by read-only `e2fsck -f -n` verification. Severe/unresolved errors remain unmounted.
