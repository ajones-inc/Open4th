# Open4th

Download:
	$ git clone --recursive https://github.com/ajones-inc/Open4th.git


To Build linux:
	$ cd Open4th/vendor/cryptopp
	$ make
	$ cd ../../../
	$ cmake -S . -B build
	$ cd build
	$ make
	
To Build Windows:
	$ cd Open4th/vendor/cryptopp
	Open the vs .sln file
	Build cryptopp
	$ cmake -S . -B build
	$ cd build
	$ make
		
To Build Windows Visual Studio:
	$ cd Open4th/vendor/cryptopp
	Open the vs .sln file
	Build cryptopp
	$ cmake -S . -B build -G "Visual Studio 17 2022"
	Open the vs .sln file
	Build Open4th