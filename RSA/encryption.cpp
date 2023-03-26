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
	bigInt b = string2bigInt(s);
	bigInt e,n;
	ifstream i("pubkey.txt");
	i >> n >> e;
	i.close();
	clock_t start, finish;
	cout << "encrypting..." << endl;
	start = clock();
	bigInt c = power(b,e,n);
	finish = clock();
	cout << "cipher is:" << c << endl; 
	cout << "encryption costs " << finish-start << endl;
	
	return 0;
}
