#include <stdio.h>
#include <time.h>

int main(int argc, char* argv[]){
    struct timespec cur_time;
    struct timespec ktime;
    clock_gettime(CLOCK_REALTIME, &cur_time);
    clock_gettime(CLOCK_BOOTTIME, &ktime);
    FILE *fp = fopen("ovs_time.txt", "w");
    fprintf(fp, "%ld %ld\n", cur_time.tv_sec, cur_time.tv_nsec);
    fprintf(fp, "%ld %ld\n", ktime.tv_sec, ktime.tv_nsec);
    fclose(fp);
}

