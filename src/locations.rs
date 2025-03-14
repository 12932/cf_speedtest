use once_cell::sync::Lazy;
use std::collections::HashMap;

pub static IATA_TO_CITY_COUNTRY: Lazy<HashMap<&'static str, (&'static str, &'static str)>> =
    Lazy::new(generate_iata_to_city_map);
pub static CCA2_TO_COUNTRY_NAME: Lazy<HashMap<&'static str, &'static str>> =
    Lazy::new(generate_cca2_to_full_country_name_map);

// all cloudflare IATAs to cities (defined at https://speed.cloudflare.com/locations)
pub fn generate_iata_to_city_map() -> HashMap<&'static str, (&'static str, &'static str)> {
    let mut map = HashMap::with_capacity(1024);
    map.insert("DXB", ("Dubai", "AE"));
    map.insert("TIA", ("Tirana", "AL"));
    map.insert("EVN", ("Yerevan", "AM"));
    map.insert("LAD", ("Luanda", "AO"));
    map.insert("EZE", ("Buenos Aires", "AR"));
    map.insert("COR", ("Córdoba", "AR"));
    map.insert("NQN", ("Neuquen", "AR"));
    map.insert("VIE", ("Vienna", "AT"));
    map.insert("ADL", ("Adelaide", "AU"));
    map.insert("BNE", ("Brisbane", "AU"));
    map.insert("CBR", ("Canberra", "AU"));
    map.insert("HBA", ("Hobart", "AU"));
    map.insert("MEL", ("Melbourne", "AU"));
    map.insert("PER", ("Perth", "AU"));
    map.insert("SYD", ("Sydney", "AU"));
    map.insert("LLK", ("Astara", "AZ"));
    map.insert("GYD", ("Baku", "AZ"));
    map.insert("BGI", ("Bridgetown", "BB"));
    map.insert("CGP", ("Chittagong", "BD"));
    map.insert("DAC", ("Dhaka", "BD"));
    map.insert("BRU", ("Brussels", "BE"));
    map.insert("OUA", ("Ouagadougou", "BF"));
    map.insert("SOF", ("Sofia", "BG"));
    map.insert("BAH", ("Manama", "BH"));
    map.insert("BWN", ("Bandar Seri Begawan", "BN"));
    map.insert("LPB", ("La Paz", "BO"));
    map.insert("QWJ", ("Americana", "BR"));
    map.insert("ARU", ("Aracatuba", "BR"));
    map.insert("BEL", ("Belém", "BR"));
    map.insert("CNF", ("Belo Horizonte", "BR"));
    map.insert("BNU", ("Blumenau", "BR"));
    map.insert("BSB", ("Brasilia", "BR"));
    map.insert("CFC", ("Cacador", "BR"));
    map.insert("VCP", ("Campinas", "BR"));
    map.insert("CAW", ("Campos dos Goytacazes", "BR"));
    map.insert("XAP", ("Chapeco", "BR"));
    map.insert("CGB", ("Cuiaba", "BR"));
    map.insert("CWB", ("Curitiba", "BR"));
    map.insert("FLN", ("Florianopolis", "BR"));
    map.insert("FOR", ("Fortaleza", "BR"));
    map.insert("GYN", ("Goiania", "BR"));
    map.insert("ITJ", ("Itajai", "BR"));
    map.insert("JOI", ("Joinville", "BR"));
    map.insert("JDO", ("Juazeiro do Norte", "BR"));
    map.insert("MAO", ("Manaus", "BR"));
    map.insert("PMW", ("Palmas", "BR"));
    map.insert("POA", ("Porto Alegre", "BR"));
    map.insert("REC", ("Recife", "BR"));
    map.insert("RAO", ("Ribeirao Preto", "BR"));
    map.insert("GIG", ("Rio de Janeiro", "BR"));
    map.insert("SSA", ("Salvador", "BR"));
    map.insert("SJP", ("São José do Rio Preto", "BR"));
    map.insert("SJK", ("São José dos Campos", "BR"));
    map.insert("GRU", ("São Paulo", "BR"));
    map.insert("SOD", ("Sorocaba", "BR"));
    map.insert("NVT", ("Timbo", "BR"));
    map.insert("UDI", ("Uberlandia", "BR"));
    map.insert("VIX", ("Vitoria", "BR"));
    map.insert("PBH", ("Thimphu", "BT"));
    map.insert("GBE", ("Gaborone", "BW"));
    map.insert("MSQ", ("Minsk", "BY"));
    map.insert("YYC", ("Calgary", "CA"));
    map.insert("YVR", ("Vancouver", "CA"));
    map.insert("YWG", ("Winnipeg", "CA"));
    map.insert("YHZ", ("Halifax", "CA"));
    map.insert("YOW", ("Ottawa", "CA"));
    map.insert("YYZ", ("Toronto", "CA"));
    map.insert("YUL", ("Montréal", "CA"));
    map.insert("YXE", ("Saskatoon", "CA"));
    map.insert("FIH", ("Kinshasa", "CD"));
    map.insert("GVA", ("Geneva", "CH"));
    map.insert("ZRH", ("Zurich", "CH"));
    map.insert("ABJ", ("Abidjan", "CI"));
    map.insert("ASK", ("Yamoussoukro", "CI"));
    map.insert("ARI", ("Arica", "CL"));
    map.insert("SCL", ("Santiago", "CL"));
    map.insert("BAQ", ("Barranquilla", "CO"));
    map.insert("BOG", ("Bogota", "CO"));
    map.insert("CLO", ("Cali", "CO"));
    map.insert("MDE", ("Medellín", "CO"));
    map.insert("SJO", ("San José", "CR"));
    map.insert("LCA", ("Nicosia", "CY"));
    map.insert("PRG", ("Prague", "CZ"));
    map.insert("TXL", ("Berlin", "DE"));
    map.insert("DUS", ("Düsseldorf", "DE"));
    map.insert("FRA", ("Frankfurt", "DE"));
    map.insert("HAM", ("Hamburg", "DE"));
    map.insert("MUC", ("Munich", "DE"));
    map.insert("STR", ("Stuttgart", "DE"));
    map.insert("JIB", ("Djibouti", "DJ"));
    map.insert("CPH", ("Copenhagen", "DK"));
    map.insert("STI", ("Santiago de los Caballeros", "DO"));
    map.insert("SDQ", ("Santo Domingo", "DO"));
    map.insert("ALG", ("Algiers", "DZ"));
    map.insert("AAE", ("Annaba", "DZ"));
    map.insert("ORN", ("Oran", "DZ"));
    map.insert("GYE", ("Guayaquil", "EC"));
    map.insert("UIO", ("Quito", "EC"));
    map.insert("TLL", ("Tallinn", "EE"));
    map.insert("CAI", ("Cairo", "EG"));
    map.insert("BCN", ("Barcelona", "ES"));
    map.insert("MAD", ("Madrid", "ES"));
    map.insert("HEL", ("Helsinki", "FI"));
    map.insert("SUV", ("Suva", "FJ"));
    map.insert("BOD", ("Bordeaux", "FR"));
    map.insert("LYS", ("Lyon", "FR"));
    map.insert("MRS", ("Marseille", "FR"));
    map.insert("CDG", ("Paris", "FR"));
    map.insert("EDI", ("Edinburgh", "GB"));
    map.insert("LHR", ("London", "GB"));
    map.insert("MAN", ("Manchester", "GB"));
    map.insert("GND", ("St. George's", "GD"));
    map.insert("TBS", ("Tbilisi", "GE"));
    map.insert("ACC", ("Accra", "GH"));
    map.insert("ATH", ("Athens", "GR"));
    map.insert("SKG", ("Thessaloniki", "GR"));
    map.insert("GUA", ("Guatemala City", "GT"));
    map.insert("GUM", ("Hagatna", "GU"));
    map.insert("GEO", ("Georgetown", "GY"));
    map.insert("HKG", ("Hong Kong", "HK"));
    map.insert("TGU", ("Tegucigalpa", "HN"));
    map.insert("ZAG", ("Zagreb", "HR"));
    map.insert("BUD", ("Budapest", "HU"));
    map.insert("DPS", ("Denpasar", "ID"));
    map.insert("CGK", ("Jakarta", "ID"));
    map.insert("JOG", ("Yogyakarta", "ID"));
    map.insert("ORK", ("Cork", "IE"));
    map.insert("DUB", ("Dublin", "IE"));
    map.insert("HFA", ("Haifa", "IL"));
    map.insert("TLV", ("Tel Aviv", "IL"));
    map.insert("AMD", ("Ahmedabad", "IN"));
    map.insert("BLR", ("Bangalore", "IN"));
    map.insert("BBI", ("Bhubaneswar", "IN"));
    map.insert("IXC", ("Chandigarh", "IN"));
    map.insert("MAA", ("Chennai", "IN"));
    map.insert("HYD", ("Hyderabad", "IN"));
    map.insert("CNN", ("Kannur", "IN"));
    map.insert("KNU", ("Kanpur", "IN"));
    map.insert("COK", ("Kochi", "IN"));
    map.insert("CCU", ("Kolkata", "IN"));
    map.insert("BOM", ("Mumbai", "IN"));
    map.insert("NAG", ("Nagpur", "IN"));
    map.insert("DEL", ("New Delhi", "IN"));
    map.insert("PAT", ("Patna", "IN"));
    map.insert("BGW", ("Baghdad", "IQ"));
    map.insert("BSR", ("Basra", "IQ"));
    map.insert("EBL", ("Erbil", "IQ"));
    map.insert("NJF", ("Najaf", "IQ"));
    map.insert("XNH", ("Nasiriyah", "IQ"));
    map.insert("ISU", ("Sulaymaniyah", "IQ"));
    map.insert("KEF", ("Reykjavík", "IS"));
    map.insert("MXP", ("Milan", "IT"));
    map.insert("PMO", ("Palermo", "IT"));
    map.insert("FCO", ("Rome", "IT"));
    map.insert("KIN", ("Kingston", "JM"));
    map.insert("AMM", ("Amman", "JO"));
    map.insert("FUK", ("Fukuoka", "JP"));
    map.insert("OKA", ("Naha", "JP"));
    map.insert("KIX", ("Osaka", "JP"));
    map.insert("NRT", ("Tokyo", "JP"));
    map.insert("MBA", ("Mombasa", "KE"));
    map.insert("NBO", ("Nairobi", "KE"));
    map.insert("PNH", ("Phnom Penh", "KH"));
    map.insert("ICN", ("Seoul", "KR"));
    map.insert("KWI", ("Kuwait City", "KW"));
    map.insert("AKX", ("Aktobe", "KZ"));
    map.insert("ALA", ("Almaty", "KZ"));
    map.insert("NQZ", ("Astana", "KZ"));
    map.insert("VTE", ("Vientiane", "LA"));
    map.insert("BEY", ("Beirut", "LB"));
    map.insert("CMB", ("Colombo", "LK"));
    map.insert("VNO", ("Vilnius", "LT"));
    map.insert("LUX", ("Luxembourg City", "LU"));
    map.insert("RIX", ("Riga", "LV"));
    map.insert("KIV", ("Chișinău", "MD"));
    map.insert("TNR", ("Antananarivo", "MG"));
    map.insert("SKP", ("Skopje", "MK"));
    map.insert("ULN", ("Ulaanbaatar", "MN"));
    map.insert("MFM", ("Macau", "MO"));
    map.insert("MRU", ("Port Louis", "MU"));
    map.insert("MLE", ("Male", "MV"));
    map.insert("GDL", ("Guadalajara", "MX"));
    map.insert("MEX", ("Mexico City", "MX"));
    map.insert("QRO", ("Queretaro", "MX"));
    map.insert("JHB", ("Johor Bahru", "MY"));
    map.insert("KUL", ("Kuala Lumpur", "MY"));
    map.insert("KCH", ("Kuching", "MY"));
    map.insert("MPM", ("Maputo", "MZ"));
    map.insert("WDH", ("Windhoek", "NA"));
    map.insert("NOU", ("Noumea", "NC"));
    map.insert("LOS", ("Lagos", "NG"));
    map.insert("AMS", ("Amsterdam", "NL"));
    map.insert("OSL", ("Oslo", "NO"));
    map.insert("KTM", ("Kathmandu", "NP"));
    map.insert("AKL", ("Auckland", "NZ"));
    map.insert("CHC", ("Christchurch", "NZ"));
    map.insert("MCT", ("Muscat", "OM"));
    map.insert("PTY", ("Panama City", "PA"));
    map.insert("LIM", ("Lima", "PE"));
    map.insert("PPT", ("Tahiti", "PF"));
    map.insert("CGY", ("Cagayan de Oro", "PH"));
    map.insert("CEB", ("Cebu", "PH"));
    map.insert("MNL", ("Manila", "PH"));
    map.insert("CRK", ("Tarlac City", "PH"));
    map.insert("ISB", ("Islamabad", "PK"));
    map.insert("KHI", ("Karachi", "PK"));
    map.insert("LHE", ("Lahore", "PK"));
    map.insert("WAW", ("Warsaw", "PL"));
    map.insert("SJU", ("San Juan", "PR"));
    map.insert("ZDM", ("Ramallah", "PS"));
    map.insert("LIS", ("Lisbon", "PT"));
    map.insert("ASU", ("Asunción", "PY"));
    map.insert("DOH", ("Doha", "QA"));
    map.insert("RUN", ("Saint-Denis", "RE"));
    map.insert("OTP", ("Bucharest", "RO"));
    map.insert("BEG", ("Belgrade", "RS"));
    map.insert("KJA", ("Krasnoyarsk", "RU"));
    map.insert("DME", ("Moscow", "RU"));
    map.insert("LED", ("Saint Petersburg", "RU"));
    map.insert("SVX", ("Yekaterinburg", "RU"));
    map.insert("KGL", ("Kigali", "RW"));
    map.insert("DMM", ("Dammam", "SA"));
    map.insert("JED", ("Jeddah", "SA"));
    map.insert("RUH", ("Riyadh", "SA"));
    map.insert("GOT", ("Gothenburg", "SE"));
    map.insert("ARN", ("Stockholm", "SE"));
    map.insert("SIN", ("Singapore", "SG"));
    map.insert("BTS", ("Bratislava", "SK"));
    map.insert("DKR", ("Dakar", "SN"));
    map.insert("PBM", ("Paramaribo", "SR"));
    map.insert("BKK", ("Bangkok", "TH"));
    map.insert("CNX", ("Chiang Mai", "TH"));
    map.insert("URT", ("Surat Thani", "TH"));
    map.insert("TUN", ("Tunis", "TN"));
    map.insert("IST", ("Istanbul", "TR"));
    map.insert("ADB", ("Izmir", "TR"));
    map.insert("POS", ("Port of Spain", "TT"));
    map.insert("KHH", ("Kaohsiung City", "TW"));
    map.insert("TPE", ("Taipei", "TW"));
    map.insert("DAR", ("Dar es Salaam", "TZ"));
    map.insert("KBP", ("Kyiv", "UA"));
    map.insert("EBB", ("Kampala", "UG"));
    map.insert("ANC", ("Anchorage", "US"));
    map.insert("PHX", ("Phoenix", "US"));
    map.insert("LAX", ("Los Angeles", "US"));
    map.insert("SMF", ("Sacramento", "US"));
    map.insert("SAN", ("San Diego", "US"));
    map.insert("SFO", ("San Francisco", "US"));
    map.insert("SJC", ("San Jose", "US"));
    map.insert("DEN", ("Denver", "US"));
    map.insert("JAX", ("Jacksonville", "US"));
    map.insert("MIA", ("Miami", "US"));
    map.insert("TLH", ("Tallahassee", "US"));
    map.insert("TPA", ("Tampa", "US"));
    map.insert("ATL", ("Atlanta", "US"));
    map.insert("HNL", ("Honolulu", "US"));
    map.insert("ORD", ("Chicago", "US"));
    map.insert("IND", ("Indianapolis", "US"));
    map.insert("BGR", ("Bangor", "US"));
    map.insert("BOS", ("Boston", "US"));
    map.insert("DTW", ("Detroit", "US"));
    map.insert("MSP", ("Minneapolis", "US"));
    map.insert("MCI", ("Kansas City", "US"));
    map.insert("STL", ("St. Louis", "US"));
    map.insert("OMA", ("Omaha", "US"));
    map.insert("LAS", ("Las Vegas", "US"));
    map.insert("EWR", ("Newark", "US"));
    map.insert("ABQ", ("Albuquerque", "US"));
    map.insert("BUF", ("Buffalo", "US"));
    map.insert("CLT", ("Charlotte", "US"));
    map.insert("RDU", ("Durham", "US"));
    map.insert("CLE", ("Cleveland", "US"));
    map.insert("CMH", ("Columbus", "US"));
    map.insert("OKC", ("Oklahoma City", "US"));
    map.insert("PDX", ("Portland", "US"));
    map.insert("PHL", ("Philadelphia", "US"));
    map.insert("PIT", ("Pittsburgh", "US"));
    map.insert("FSD", ("Sioux Falls", "US"));
    map.insert("MEM", ("Memphis", "US"));
    map.insert("BNA", ("Nashville", "US"));
    map.insert("AUS", ("Austin", "US"));
    map.insert("DFW", ("Dallas", "US"));
    map.insert("IAH", ("Houston", "US"));
    map.insert("MFE", ("McAllen", "US"));
    map.insert("SAT", ("San Antonio", "US"));
    map.insert("SLC", ("Salt Lake City", "US"));
    map.insert("IAD", ("Ashburn", "US"));
    map.insert("ORF", ("Norfolk", "US"));
    map.insert("RIC", ("Richmond", "US"));
    map.insert("SEA", ("Seattle", "US"));
    map.insert("DAD", ("Da Nang", "VN"));
    map.insert("HAN", ("Hanoi", "VN"));
    map.insert("SGN", ("Ho Chi Minh City", "VN"));
    map.insert("CPT", ("Cape Town", "ZA"));
    map.insert("DUR", ("Durban", "ZA"));
    map.insert("JNB", ("Johannesburg", "ZA"));
    map.insert("LUN", ("Lusaka", "ZM"));
    map.insert("HRE", ("Harare", "ZW"));
    map
}

// create a mapping of cca2 to full country name
pub fn generate_cca2_to_full_country_name_map() -> HashMap<&'static str, &'static str> {
    let mut map = HashMap::with_capacity(512);
    map.insert("AF", "Afghanistan");
    map.insert("AX", "Åland Islands");
    map.insert("AL", "Albania");
    map.insert("DZ", "Algeria");
    map.insert("AS", "American Samoa");
    map.insert("AD", "Andorra");
    map.insert("AO", "Angola");
    map.insert("AI", "Anguilla");
    map.insert("AQ", "Antarctica");
    map.insert("AG", "Antigua and Barbuda");
    map.insert("AR", "Argentina");
    map.insert("AM", "Armenia");
    map.insert("AW", "Aruba");
    map.insert("AU", "Australia");
    map.insert("AT", "Austria");
    map.insert("AZ", "Azerbaijan");
    map.insert("BS", "Bahamas");
    map.insert("BH", "Bahrain");
    map.insert("BD", "Bangladesh");
    map.insert("BB", "Barbados");
    map.insert("BY", "Belarus");
    map.insert("BE", "Belgium");
    map.insert("BZ", "Belize");
    map.insert("BJ", "Benin");
    map.insert("BM", "Bermuda");
    map.insert("BT", "Bhutan");
    map.insert("BO", "Bolivia, Plurinational State of");
    map.insert("BQ", "Bonaire, Sint Eustatius and Saba");
    map.insert("BA", "Bosnia and Herzegovina");
    map.insert("BW", "Botswana");
    map.insert("BV", "Bouvet Island");
    map.insert("BR", "Brazil");
    map.insert("IO", "British Indian Ocean Territory");
    map.insert("BN", "Brunei Darussalam");
    map.insert("BG", "Bulgaria");
    map.insert("BF", "Burkina Faso");
    map.insert("BI", "Burundi");
    map.insert("KH", "Cambodia");
    map.insert("CM", "Cameroon");
    map.insert("CA", "Canada");
    map.insert("CV", "Cabo Verde");
    map.insert("KY", "Cayman Islands");
    map.insert("CF", "Central African Republic");
    map.insert("TD", "Chad");
    map.insert("CL", "Chile");
    map.insert("CN", "China");
    map.insert("CX", "Christmas Island");
    map.insert("CC", "Cocos (Keeling) Islands");
    map.insert("CO", "Colombia");
    map.insert("KM", "Comoros");
    map.insert("CG", "Congo");
    map.insert("CD", "Congo, Democratic Republic of the");
    map.insert("CK", "Cook Islands");
    map.insert("CR", "Costa Rica");
    map.insert("CI", "Côte d'Ivoire");
    map.insert("HR", "Croatia");
    map.insert("CU", "Cuba");
    map.insert("CW", "Curaçao");
    map.insert("CY", "Cyprus");
    map.insert("CZ", "Czechia");
    map.insert("DK", "Denmark");
    map.insert("DJ", "Djibouti");
    map.insert("DM", "Dominica");
    map.insert("DO", "Dominican Republic");
    map.insert("EC", "Ecuador");
    map.insert("EG", "Egypt");
    map.insert("SV", "El Salvador");
    map.insert("GQ", "Equatorial Guinea");
    map.insert("ER", "Eritrea");
    map.insert("EE", "Estonia");
    map.insert("ET", "Ethiopia");
    map.insert("FK", "Falkland Islands (Malvinas)");
    map.insert("FO", "Faroe Islands");
    map.insert("FJ", "Fiji");
    map.insert("FI", "Finland");
    map.insert("FR", "France");
    map.insert("GF", "French Guiana");
    map.insert("PF", "French Polynesia");
    map.insert("TF", "French Southern Territories");
    map.insert("GA", "Gabon");
    map.insert("GM", "Gambia");
    map.insert("GE", "Georgia");
    map.insert("DE", "Germany");
    map.insert("GH", "Ghana");
    map.insert("GI", "Gibraltar");
    map.insert("GR", "Greece");
    map.insert("GL", "Greenland");
    map.insert("GD", "Grenada");
    map.insert("GP", "Guadeloupe");
    map.insert("GU", "Guam");
    map.insert("GT", "Guatemala");
    map.insert("GG", "Guernsey");
    map.insert("GN", "Guinea");
    map.insert("GW", "Guinea-Bissau");
    map.insert("GY", "Guyana");
    map.insert("HT", "Haiti");
    map.insert("HM", "Heard Island and McDonald Islands");
    map.insert("VA", "Holy See");
    map.insert("HN", "Honduras");
    map.insert("HK", "Hong Kong");
    map.insert("HU", "Hungary");
    map.insert("IS", "Iceland");
    map.insert("IN", "India");
    map.insert("ID", "Indonesia");
    map.insert("IR", "Iran, Islamic Republic of");
    map.insert("IQ", "Iraq");
    map.insert("IE", "Ireland");
    map.insert("IM", "Isle of Man");
    map.insert("IL", "Israel");
    map.insert("IT", "Italy");
    map.insert("JM", "Jamaica");
    map.insert("JP", "Japan");
    map.insert("JE", "Jersey");
    map.insert("JO", "Jordan");
    map.insert("KZ", "Kazakhstan");
    map.insert("KE", "Kenya");
    map.insert("KI", "Kiribati");
    map.insert("KP", "Korea, Democratic People's Republic of");
    map.insert("KR", "Korea, Republic of");
    map.insert("XK", "Kosovo");
    map.insert("KW", "Kuwait");
    map.insert("KG", "Kyrgyzstan");
    map.insert("LA", "Lao People's Democratic Republic");
    map.insert("LV", "Latvia");
    map.insert("LB", "Lebanon");
    map.insert("LS", "Lesotho");
    map.insert("LR", "Liberia");
    map.insert("LY", "Libya");
    map.insert("LI", "Liechtenstein");
    map.insert("LT", "Lithuania");
    map.insert("LU", "Luxembourg");
    map.insert("MO", "Macao");
    map.insert("MK", "North Macedonia");
    map.insert("MG", "Madagascar");
    map.insert("MW", "Malawi");
    map.insert("MY", "Malaysia");
    map.insert("MV", "Maldives");
    map.insert("ML", "Mali");
    map.insert("MT", "Malta");
    map.insert("MH", "Marshall Islands");
    map.insert("MQ", "Martinique");
    map.insert("MR", "Mauritania");
    map.insert("MU", "Mauritius");
    map.insert("YT", "Mayotte");
    map.insert("MX", "Mexico");
    map.insert("FM", "Micronesia, Federated States of");
    map.insert("MD", "Moldova, Republic of");
    map.insert("MC", "Monaco");
    map.insert("MN", "Mongolia");
    map.insert("ME", "Montenegro");
    map.insert("MS", "Montserrat");
    map.insert("MA", "Morocco");
    map.insert("MZ", "Mozambique");
    map.insert("MM", "Myanmar");
    map.insert("NA", "Namibia");
    map.insert("NR", "Nauru");
    map.insert("NP", "Nepal");
    map.insert("NL", "Netherlands");
    map.insert("NC", "New Caledonia");
    map.insert("NZ", "New Zealand");
    map.insert("NI", "Nicaragua");
    map.insert("NE", "Niger");
    map.insert("NG", "Nigeria");
    map.insert("NU", "Niue");
    map.insert("NF", "Norfolk Island");
    map.insert("MP", "Northern Mariana Islands");
    map.insert("NO", "Norway");
    map.insert("OM", "Oman");
    map.insert("PK", "Pakistan");
    map.insert("PW", "Palau");
    map.insert("PS", "Palestine, State of");
    map.insert("PA", "Panama");
    map.insert("PG", "Papua New Guinea");
    map.insert("PY", "Paraguay");
    map.insert("PE", "Peru");
    map.insert("PH", "Philippines");
    map.insert("PN", "Pitcairn");
    map.insert("PL", "Poland");
    map.insert("PT", "Portugal");
    map.insert("PR", "Puerto Rico");
    map.insert("QA", "Qatar");
    map.insert("RE", "Réunion");
    map.insert("RO", "Romania");
    map.insert("RU", "Russian Federation");
    map.insert("RW", "Rwanda");
    map.insert("BL", "Saint Barthélemy");
    map.insert("SH", "Saint Helena, Ascension and Tristan da Cunha");
    map.insert("KN", "Saint Kitts and Nevis");
    map.insert("LC", "Saint Lucia");
    map.insert("MF", "Saint Martin (French part)");
    map.insert("PM", "Saint Pierre and Miquelon");
    map.insert("VC", "Saint Vincent and the Grenadines");
    map.insert("WS", "Samoa");
    map.insert("SM", "San Marino");
    map.insert("ST", "Sao Tome and Principe");
    map.insert("SA", "Saudi Arabia");
    map.insert("SN", "Senegal");
    map.insert("RS", "Serbia");
    map.insert("SC", "Seychelles");
    map.insert("SL", "Sierra Leone");
    map.insert("SG", "Singapore");
    map.insert("SX", "Sint Maarten (Dutch part)");
    map.insert("SK", "Slovakia");
    map.insert("SI", "Slovenia");
    map.insert("SB", "Solomon Islands");
    map.insert("SO", "Somalia");
    map.insert("ZA", "South Africa");
    map.insert("GS", "South Georgia and the South Sandwich Islands");
    map.insert("SS", "South Sudan");
    map.insert("ES", "Spain");
    map.insert("LK", "Sri Lanka");
    map.insert("SD", "Sudan");
    map.insert("SR", "Suriname");
    map.insert("SJ", "Svalbard and Jan Mayen");
    map.insert("SZ", "Eswatini");
    map.insert("SE", "Sweden");
    map.insert("CH", "Switzerland");
    map.insert("SY", "Syrian Arab Republic");
    map.insert("TW", "Taiwan, Province of China");
    map.insert("TJ", "Tajikistan");
    map.insert("TZ", "Tanzania, United Republic of");
    map.insert("TH", "Thailand");
    map.insert("TL", "Timor-Leste");
    map.insert("TG", "Togo");
    map.insert("TK", "Tokelau");
    map.insert("TO", "Tonga");
    map.insert("TT", "Trinidad and Tobago");
    map.insert("TN", "Tunisia");
    map.insert("TR", "Türkiye");
    map.insert("TM", "Turkmenistan");
    map.insert("TC", "Turks and Caicos Islands");
    map.insert("TV", "Tuvalu");
    map.insert("UG", "Uganda");
    map.insert("UA", "Ukraine");
    map.insert("AE", "United Arab Emirates");
    map.insert("GB", "United Kingdom of Great Britain and Northern Ireland");
    map.insert("US", "United States of America");
    map.insert("UM", "United States Minor Outlying Islands");
    map.insert("UY", "Uruguay");
    map.insert("UZ", "Uzbekistan");
    map.insert("VU", "Vanuatu");
    map.insert("VE", "Venezuela, Bolivarian Republic of");
    map.insert("VN", "Viet Nam");
    map.insert("VG", "Virgin Islands, British");
    map.insert("VI", "Virgin Islands, U.S.");
    map.insert("WF", "Wallis and Futuna");
    map.insert("EH", "Western Sahara");
    map.insert("YE", "Yemen");
    map.insert("ZM", "Zambia");
    map.insert("ZW", "Zimbabwe");

    // cloudflare specific
    map.insert("T1", "Tor Network");
    map.insert("XX", "No country");

    map
}
