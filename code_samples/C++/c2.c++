#include <iostream>
#include <vector>
using namespace std;
int main() {
    vector<int>* v = new vector<int>(5);
    delete v;
    cout << v->at(0) << endl; // use-after-delete
    return 0;
}
