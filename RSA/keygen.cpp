#include <iostream>
#include <fstream>
#include <cstdlib>
#include <time.h>
#include "bigInt.h"
#include "gcd.h"
#include "mrTest.h"
#include "power.h"
#include "random.h"

using namespace std;

// int main()
// {
// 	ofstream o1("pubkey.txt");
// 	ofstream o2("prikey.txt");
// 	setRandom(time(NULL));
// 	clock_t start, finish;
	
// 	cout << "generating p and q..." << endl;
// 	start = clock();
// 	bigInt p,q;
// 	p = createprime();
// 	q = createprime();
// 	while(p == q) q = createprime();
// 	finish = clock();
// 	cout << "generate p and q costs " << finish-start << endl;
	
// 	bigInt n = p * q;
// 	bigInt fai = (p-bigInt("1"))*(q-bigInt("1"));
	
// 	cout << "generating d and e..." << endl;
// 	bigInt d,e;
// 	start = clock();
// 	d = bigInt("3");
// 	while(!(gcd(d,fai) == bigInt("1")))
// 		d = d + bigInt("2");
// 	e = inv(d,fai);
// 	finish = clock();
// 	cout << "generate d and e costs " << finish-start << endl;
	
// 	o1 << n << " " << e;
// 	o2 << n << " " << d << " " << p << " " << q;
	
// 	o1.close();
// 	o2.close();
// 	return 0;
// }