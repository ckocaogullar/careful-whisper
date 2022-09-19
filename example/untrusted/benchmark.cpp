#include "benchmark.h"
#include "stdio.h"


// Read the CPU cycle
uint64_t read_tsc() {
    // _mm_lfence();  // optionally wait for earlier insns to retire before reading the clock
    return __rdtsc();
    // _mm_lfence();  // optionally block later instructions until rdtsc retires
}

// Calculate the time passed in microseconds
uint64_t calc_time_passed(chronometre_t chronometre){
	if(TIME_TYPE == (my_time_t)CYCLES){
        return chronometre.end_cycle - chronometre.start_cycle;
    } else if (TIME_TYPE == (my_time_t) CPU_TIME || TIME_TYPE == (my_time_t) WALL_TIME)
    {
        return (chronometre.end_microsecs.tv_sec - chronometre.start_microsecs.tv_sec) * 1000000 + (chronometre.end_microsecs.tv_nsec - chronometre.start_microsecs.tv_nsec) / 1000;
    }
    printf("Called the calc_time_passed\n");
}

void start_chronometre(chronometre_t *chronometre){
    if(TIME_TYPE == (my_time_t)CYCLES){
        chronometre->start_cycle = read_tsc();

    } else if (TIME_TYPE == (my_time_t) WALL_TIME)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &(*chronometre).start_microsecs);
    } else if (TIME_TYPE == (my_time_t) CPU_TIME)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(*chronometre).start_microsecs);
    }
}


void stop_chronometre(chronometre_t *chronometre){
    if(TIME_TYPE == (my_time_t)CYCLES){
        chronometre->end_cycle = read_tsc();
    } else if (TIME_TYPE == (my_time_t) WALL_TIME)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &(*chronometre).end_microsecs);
    } else if (TIME_TYPE == (my_time_t) CPU_TIME)
    {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(*chronometre).end_microsecs);
    }
}