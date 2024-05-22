#include "c_pointer.h"

// 写一个调用int类型的数组指针，并且重新排序的函数
void reorder(int *arr, int size) {
    int i, j, temp;
    for (i = 0; i < size - 1; i++) {
        for (j = 0; j < size - 1 - i; j++) {
            if (arr[j] > arr[j + 1]) {
                temp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = temp;
            }
        }
    }
}


// malloc一个字符串数组，调用deleteSpace函数，删除空格，然后打印字符串
void decoder()
{
    char *arr = (char *)malloc(100 * sizeof(char));
    char temp[70] = "Hello World , USTCers. You all were have great four years in USTC.";
    strcpy(arr, temp);
    deleteSpace(arr, strlen(arr));
    printf("The string after delete space is: %s\n", arr);
    free(arr);
}
