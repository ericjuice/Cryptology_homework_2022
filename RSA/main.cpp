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

int main()
{
	ofstream o1("pubkey.txt");
	ofstream o2("prikey.txt");
	setRandom(time(NULL));
	string s;
	clock_t start, finish;
	cout<<"Input a string\n";
	cin >> s;
	bigInt b = string2bigInt(s);
	cout << string2bigInt(s) << endl;
	
	
	cout << "generating p and q..." << endl;
	start = clock();
	bigInt p,q;
	p = createprime();
	q = createprime();
	while(p == q) q = createprime();
	finish = clock();
	cout << "p = " << p << endl;
	cout << "q = " << q << endl;
	cout << "generate p and q costs " << finish-start << endl;
	
	bigInt n = p * q;
	bigInt fai = (p-bigInt("1"))*(q-bigInt("1"));
	
	cout << "generating d and e..." << endl;
	bigInt d,e;
	start = clock();
	d = bigInt("3");
	while(!(gcd(d,fai) == bigInt("1")))
		d = d + bigInt("2");
	e = inv(d,fai);
	finish = clock();
	cout << "d = " << d << endl;
	cout << "e = " << e << endl;
	cout << "generate d and e costs " << finish-start << endl;
	
	o1 << n << " " << e;
	o2 << n << " " << d << " " << p << " " << q;
	
	o1.close();
	o2.close();
	
	
	cout << "encrypting..." << endl;
	start = clock();
	bigInt c = power(b,e,n);
	finish = clock();
	cout << "cipher is:" << c << endl; 
	cout << "encryption costs " << finish-start << endl;
	
	cout << "decrypting..." << endl;
	start = clock();
	bigInt text = power(c,d,n);
	cout << "plain is:" << text << endl; 
	cout << "text is:" << bigInt2string(text) << endl;
	finish = clock();
	cout << "decryption costs " << finish-start << endl;
 	return 0;
}