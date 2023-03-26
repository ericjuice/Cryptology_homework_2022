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
	string s;
	cin >> s;
	bigInt c(s);
	bigInt d,n;
	ifstream i("prikey.txt");
	i >> n >> d;
	i.close();
	clock_t start, finish;
	cout << "decrypting..." << endl;
	start = clock();
	bigInt text = power(c,d,n);
	cout << "plain is:" << text << endl; 
	cout << "text is:" << bigInt2string(text) << endl;
	finish = clock();
	cout << "decryption costs " << finish-start << endl;
 	return 0;
}
