:tocdepth: 3

base/protocols/rdp/consts.zeek
==============================
.. zeek:namespace:: RDP


:Namespace: RDP

Summary
~~~~~~~
Constants
#########
==================================================================================================== =
:zeek:id:`RDP::builds`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`             
:zeek:id:`RDP::cert_types`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         
:zeek:id:`RDP::color_depths`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`       
:zeek:id:`RDP::encryption_levels`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  
:zeek:id:`RDP::encryption_methods`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
:zeek:id:`RDP::failure_codes`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      
:zeek:id:`RDP::high_color_depths`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`  
:zeek:id:`RDP::languages`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`          
:zeek:id:`RDP::results`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`            
:zeek:id:`RDP::security_protocols`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` 
==================================================================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: RDP::builds

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2195] = "RDP 5.0",
            [7601] = "RDP 7.1",
            [6001] = "RDP 6.1",
            [6000] = "RDP 6.0",
            [419] = "RDP 4.0",
            [25282] = "RDP 8.0 (Mac)",
            [3790] = "RDP 5.2",
            [2600] = "RDP 5.1",
            [6002] = "RDP 6.2",
            [2221] = "RDP 5.0",
            [7600] = "RDP 7.0",
            [9600] = "RDP 8.1",
            [25189] = "RDP 8.0 (Mac)",
            [9200] = "RDP 8.0"
         }



.. zeek:id:: RDP::cert_types

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "X.509",
            [1] = "RSA"
         }



.. zeek:id:: RDP::color_depths

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [8] = "32bit",
            [4] = "15bit",
            [2] = "16bit",
            [1] = "24bit"
         }



.. zeek:id:: RDP::encryption_levels

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "None",
            [2] = "Client compatible",
            [4] = "FIPS",
            [1] = "Low",
            [3] = "High"
         }



.. zeek:id:: RDP::encryption_methods

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "None",
            [10] = "FIPS",
            [8] = "56bit",
            [2] = "128bit",
            [1] = "40bit"
         }



.. zeek:id:: RDP::failure_codes

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "SSL_NOT_ALLOWED_BY_SERVER",
            [5] = "HYBRID_REQUIRED_BY_SERVER",
            [3] = "SSL_CERT_NOT_ON_SERVER",
            [6] = "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            [4] = "INCONSISTENT_FLAGS",
            [1] = "SSL_REQUIRED_BY_SERVER"
         }



.. zeek:id:: RDP::high_color_depths

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [15] = "15bit",
            [16] = "16bit",
            [8] = "8bit",
            [4] = "4bit",
            [24] = "24bit"
         }



.. zeek:id:: RDP::languages

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [1154] = "Occitan",
            [6153] = "English - Ireland",
            [1080] = "Faroese",
            [11273] = "English - Trinidad",
            [1153] = "Maori - New Zealand",
            [1140] = "Guarani - Paraguay",
            [1155] = "Corsican",
            [14337] = "Arabic - U.A.E.",
            [1033] = "English - United States",
            [1129] = "Ibibio - Nigeria",
            [1053] = "Swedish",
            [1134] = "Luxembourgish",
            [12297] = "English - Zimbabwe",
            [3079] = "German - Austria",
            [2070] = "Portuguese - Portugal",
            [5124] = "Chinese - Macao SAR",
            [1070] = "Sorbian",
            [1079] = "Georgian",
            [9226] = "Spanish - Colombia",
            [1089] = "Swahili",
            [1105] = "Tibetan - People's Republic of China",
            [17417] = "English - Malaysia",
            [1164] = "Dari",
            [1064] = "Tajik",
            [14346] = "Spanish - Uruguay",
            [1109] = "Burmese",
            [1158] = "K'iche",
            [1075] = "Venda",
            [4122] = "Croatian (Bosnia/Herzegovina)",
            [1128] = "Hausa - Nigeria",
            [1137] = "Kanuri - Nigeria",
            [10249] = "English - Belize",
            [11265] = "Arabic - Jordan",
            [1081] = "Hindi",
            [4097] = "Arabic - Libya",
            [1036] = "French - France",
            [1093] = "Bengali (India)",
            [1133] = "Bashkir",
            [1039] = "Icelandic",
            [1059] = "Belarusian",
            [1088] = "Kyrgyz (Cyrillic)",
            [5146] = "Bosnian (Bosnia/Herzegovina)",
            [17418] = "Spanish - El Salvador",
            [22538] = "Spanish - Latin America",
            [6156] = "French - Monaco",
            [1091] = "Uzbek (Latin)",
            [2128] = "Mongolian (Mongolian)",
            [1043] = "Dutch - Netherlands",
            [1029] = "Czech",
            [1052] = "Albanian - Albania",
            [2145] = "Nepali - India",
            [6154] = "Spanish - Panama",
            [1115] = "Sinhalese - Sri Lanka",
            [1135] = "Greenlandic",
            [9228] = "French - Democratic Rep. of Congo",
            [1090] = "Turkmen",
            [1152] = "Uighur - China",
            [1065] = "Farsi",
            [3098] = "Serbian (Cyrillic)",
            [2144] = "Kashmiri",
            [10241] = "Arabic - Syria",
            [2064] = "Italian - Switzerland",
            [1047] = "Rhaeto-Romanic",
            [1160] = "Wolof",
            [3076] = "Chinese - Hong Kong SAR",
            [2067] = "Dutch - Belgium",
            [13313] = "Arabic - Kuwait",
            [2049] = "Arabic - Iraq",
            [1030] = "Danish",
            [3073] = "Arabic - Egypt",
            [15370] = "Spanish - Paraguay",
            [1131] = "Quecha - Bolivia",
            [1077] = "Zulu",
            [16394] = "Spanish - Bolivia",
            [2055] = "German - Switzerland",
            [1026] = "Bulgarian",
            [1082] = "Maltese",
            [1071] = "FYRO Macedonian",
            [8204] = "French - Reunion",
            [12300] = "French - Cote d'Ivoire",
            [13321] = "English - Philippines",
            [1121] = "Nepali",
            [20490] = "Spanish - Puerto Rico",
            [3084] = "French - Canada",
            [2155] = "Quecha - Ecuador",
            [1114] = "Syriac",
            [1066] = "Vietnamese",
            [1092] = "Tatar",
            [5132] = "French - Luxembourg",
            [1132] = "Sepedi",
            [14348] = "French - Morocco",
            [2074] = "Serbian (Latin)",
            [1098] = "Telugu",
            [1156] = "Alsatian",
            [1055] = "Turkish",
            [7178] = "Spanish - Dominican Republic",
            [1083] = "Sami (Lappish)",
            [4106] = "Spanish - Guatemala",
            [3081] = "English - Australia",
            [5129] = "English - New Zealand",
            [1146] = "Mapudungun",
            [1037] = "Hebrew",
            [2057] = "English - United Kingdom",
            [1159] = "Kinyarwanda",
            [2108] = "Irish",
            [1032] = "Greek",
            [2058] = "Spanish - Mexico",
            [1049] = "Russian",
            [1067] = "Armenian - Armenia",
            [1054] = "Thai",
            [1143] = "Somali",
            [1031] = "German - Germany",
            [4108] = "French - Switzerland",
            [1103] = "Sanskrit",
            [15369] = "English - Hong Kong SAR",
            [9225] = "English - Caribbean",
            [1097] = "Tamil",
            [8201] = "English - Jamaica",
            [15361] = "Arabic - Bahrain",
            [2115] = "Uzbek (Cyrillic)",
            [1062] = "Latvian",
            [4105] = "English - Canada",
            [1120] = "Kashmiri (Arabic)",
            [7169] = "Arabic - Tunisia",
            [2143] = "Tamazight (Latin)",
            [2118] = "Punjabi (Pakistan)",
            [13324] = "French - Mali",
            [3082] = "Spanish - Spain (Modern Sort)",
            [8202] = "Spanish - Venezuela",
            [12289] = "Arabic - Lebanon",
            [7180] = "French - West Indies",
            [1142] = "Latin",
            [1074] = "Tswana",
            [1058] = "Ukrainian",
            [5130] = "Spanish - Costa Rica",
            [1141] = "Hawaiian - United States",
            [1042] = "Korean",
            [1086] = "Malay - Malaysia",
            [8193] = "Arabic - Oman",
            [1106] = "Welsh",
            [1122] = "French - West Indies",
            [1095] = "Gujarati",
            [18442] = "Spanish - Honduras",
            [1094] = "Punjabi",
            [1087] = "Kazakh",
            [1099] = "Kannada",
            [1035] = "Finnish",
            [11274] = "Spanish - Argentina",
            [1069] = "Basque",
            [1111] = "Konkani",
            [1126] = "Edo",
            [10252] = "French - Senegal",
            [1078] = "Afrikaans - South Africa",
            [1068] = "Azeri (Latin)",
            [1124] = "Filipino",
            [2080] = "Urdu - India",
            [2052] = "Chinese - People's Republic of China",
            [2068] = "Norwegian (Nynorsk)",
            [1044] = "Norwegian (Bokmal)",
            [7177] = "English - South Africa",
            [1034] = "Spanish - Spain (Traditional Sort)",
            [1028] = "Chinese - Taiwan",
            [1084] = "Scottish Gaelic",
            [13322] = "Spanish - Chile",
            [1051] = "Slovak",
            [1096] = "Oriya",
            [2110] = "Malay - Brunei Darussalam",
            [1116] = "Cherokee - United States",
            [58380] = "French - North Africa",
            [1038] = "Hungarian",
            [1061] = "Estonian",
            [16385] = "Arabic - Qatar",
            [1112] = "Manipuri",
            [2060] = "French - Belgium",
            [16393] = "English - India",
            [1025] = "Arabic - Saudi Arabia",
            [1119] = "Tamazight (Arabic)",
            [1104] = "Mongolian (Cyrillic)",
            [2129] = "Tibetan - Bhutan",
            [15372] = "French - Haiti",
            [1073] = "Tsonga",
            [19466] = "Spanish - Nicaragua",
            [6145] = "Arabic - Morocco",
            [1138] = "Oromo",
            [1117] = "Inuktitut",
            [10250] = "Spanish - Peru",
            [1041] = "Japanese",
            [4100] = "Chinese - Singapore",
            [21514] = "Spanish - United States",
            [1056] = "Urdu",
            [1100] = "Malayalam",
            [1102] = "Marathi",
            [1125] = "Divehi",
            [1101] = "Assamese",
            [2137] = "Sindhi - Pakistan",
            [2072] = "Romanian - Moldava",
            [2092] = "Azeri (Cyrillic)",
            [1130] = "Yoruba",
            [1127] = "Fulfulde - Nigeria",
            [1148] = "Mohawk",
            [1139] = "Tigrigna - Ethiopia",
            [1048] = "Romanian",
            [12298] = "Spanish - Ecuador",
            [1110] = "Galician",
            [18441] = "English - Singapore",
            [5121] = "Arabic - Algeria",
            [2077] = "Swedish - Finland",
            [1076] = "Xhosa",
            [2073] = "Russian - Moldava",
            [1108] = "Lao",
            [1136] = "Igbo - Nigeria",
            [1150] = "Breton",
            [1113] = "Sindhi - India",
            [1050] = "Croatian",
            [1157] = "Yakut",
            [4103] = "German - Luxembourg",
            [1123] = "Pashto",
            [1057] = "Indonesian",
            [2163] = "Tigrigna - Eritrea",
            [9217] = "Arabic - Yemen",
            [11276] = "French - Cameroon",
            [1107] = "Khmer",
            [2117] = "Bengali (Bangladesh)",
            [1063] = "Lithuanian",
            [1085] = "Yiddish",
            [14345] = "English - Indonesia",
            [1072] = "Sutu",
            [1279] = "HID (Human Interface Device)",
            [3179] = "Quecha - Peru\x09CB",
            [1145] = "Papiamentu",
            [5127] = "German - Liechtenstein",
            [1144] = "Yi",
            [1027] = "Catalan",
            [1060] = "Slovenian",
            [1046] = "Portuguese - Brazil",
            [1118] = "Amharic - Ethiopia",
            [1040] = "Italian - Italy",
            [1045] = "Polish"
         }



.. zeek:id:: RDP::results

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "Success",
            [2] = "Resources not available",
            [4] = "Locked conference",
            [1] = "User rejected",
            [3] = "Rejected for symmetry breaking"
         }



.. zeek:id:: RDP::security_protocols

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "RDP",
            [8] = "HYBRID_EX",
            [2] = "HYBRID",
            [1] = "SSL"
         }




