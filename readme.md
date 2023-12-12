1. sudo apt-get install dh-make 
2. sudo apt-get install dkms
3. sudo cp -a fdeion /usr/src/fdeion-1.0
	3.1 sudo dkms add -m fdeion -v 1.0
4. sudo dkms build -m fdeion -v 1.0 
5. sudo dkms mkdeb -m fdeion -v 1.0
