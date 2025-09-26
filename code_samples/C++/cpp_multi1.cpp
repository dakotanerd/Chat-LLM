#include <iostream>
#include <vector>
#include <cstring>
#include <cstdlib>
using namespace std;

void run() {
    char buf[5];
    strcpy(buf, "Overflow"); // buffer overflow

    vector<int>* v = new vector<int>(5);
    delete v;
    cout << v->at(0) << endl; // use-after-delete

    string token = "secret123"; // hardcoded token
    cout << "Token: " << token << endl;

    system("ls -la"); // command execution
}

int main() {
    run();
    return 0;
}
