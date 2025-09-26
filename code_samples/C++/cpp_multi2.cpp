#include <iostream>
#include <vector>
using namespace std;

int add(int a, int b) { return a + b; }

int main() {
    vector<int> nums = {1,2,3};
    for(int n: nums) cout << n << " ";
    cout << endl;
    cout << "Sum: " << add(5,7) << endl;
    return 0;
}
