#include <x86intrin.h>
#include "settings.h"
#include "time.h"
#include "stdint.h"

// Enum for type of time to be measured. 0 for CPU cycle, 1 for calendar clock
typedef enum my_time_type
{
	CYCLES,
	WALL_TIME,
    CPU_TIME
} my_time_t;

typedef struct chronometre_type
{
	uint64_t start_cycle;
	uint64_t end_cycle;
	timespec start_microsecs;
	timespec end_microsecs;
} chronometre_t;


uint64_t calc_time_passed(chronometre_t chronometre);
void start_chronometre(chronometre_t *chronometre);
void stop_chronometre(chronometre_t *chronometre);