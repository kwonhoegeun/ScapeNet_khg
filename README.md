# ScapeNet-khg

Use and build guide:

	You should install "libpcap-dev" before build.

	./mkfifo.sh		# Create a build directory and fifo file.
	cd build; cmake ..	# Configure the project.
	cmake --build . | make	# Build all default targets.

	echo k 6 > .write_sense
	echo p 6 > .write_sense
