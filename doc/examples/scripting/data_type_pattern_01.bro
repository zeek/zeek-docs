event bro_init()
    {
    local test_string = "The quick brown fox jumps over the lazy dog.";
    local test_pattern = /quick|lazy/;
    
    if ( test_pattern in test_string )
        {
        local results = split(test_string, test_pattern);
        print results[1];
        print results[2];
        print results[3];
        }
    }
