default: scan

scan.o: scan.cpp
	g++ -std=c++20 -c scan.cpp -o scan.o -lpthread -latomic

scan: scan.o
	g++ -std=c++20 scan.o -o scan -lpthread -latomic

clean:
	-rm -f main.o
	-rm -f main
