#include <iostream>
#include <cstring>
using namespace std;
int main() {
    char buf[5];
    strcpy(buf, "Overflow"); // buffer overflow
    cout << buf << endl;
    return 0;
}
