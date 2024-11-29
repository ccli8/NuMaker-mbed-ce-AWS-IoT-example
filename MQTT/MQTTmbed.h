#if !defined(MQTT_MBED_H)
#define MQTT_MBED_H

#include "mbed.h"

class Countdown
{
public:
    Countdown() : t()
    {
  
    }
    
    Countdown(int ms) : t()
    {
        countdown_ms(ms);   
    }
    

    bool expired()
    {
        return (t.elapsed_time()).count()/1000 >= interval_end_ms;
    }
    
    void countdown_ms(unsigned long ms)  
    {
        t.stop();
        interval_end_ms = ms;
        t.reset();
        t.start();
    }
    
    void countdown(int seconds)
    {
        countdown_ms((unsigned long)seconds * 1000L);
    }
    
    int left_ms()
    {
        return interval_end_ms - (t.elapsed_time()).count()/1000;
    }
    
private:
    Timer t;
    unsigned long interval_end_ms; 
};

#endif