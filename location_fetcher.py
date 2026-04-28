# /// script
# dependencies = [
#   "requests",
# ]
# ///

import requests

r = requests.get(
    "https://speed.cloudflare.com/locations",
    headers={"Referer": "https://speed.cloudflare.com/"},
)
locs_json = r.json()

# Extra colos not returned by the Cloudflare endpoint
extra_colos = [
    {"iata": "BBI", "city": "Bhubaneswar", "cca2": "IN"},
    {"iata": "CMN", "city": "Casablanca", "cca2": "MA"},
    {"iata": "CUR", "city": "Willemstad", "cca2": "CW"},
    {"iata": "EDI", "city": "Edinburgh", "cca2": "GB"},
    {"iata": "ITJ", "city": "Itajaí", "cca2": "BR"},
    {"iata": "JSR", "city": "Jashore", "cca2": "BD"},
    {"iata": "KHV", "city": "Khabarovsk", "cca2": "RU"},
    {"iata": "KIV", "city": "Chișinău", "cca2": "MD"},
    {"iata": "KLD", "city": "Tver", "cca2": "RU"},
    {"iata": "MDL", "city": "Mandalay", "cca2": "MM"},
    {"iata": "MFE", "city": "McAllen", "cca2": "US"},
    {"iata": "MGM", "city": "Montgomery", "cca2": "US"},
    {"iata": "ORK", "city": "Cork", "cca2": "IE"},
    {"iata": "PAP", "city": "Port-au-Prince", "cca2": "HT"},
    {"iata": "RGN", "city": "Yangon", "cca2": "MM"},
    {"iata": "SVX", "city": "Yekaterinburg", "cca2": "RU"},
    {"iata": "TAS", "city": "Tashkent", "cca2": "UZ"},
    {"iata": "WLG", "city": "Wellington", "cca2": "NZ"},
]

locs_json.extend(extra_colos)
sorted_data = sorted(locs_json, key=lambda x: x['iata'])

map_code = ""

for entry in sorted_data:
    iata = entry["iata"]
    city = entry["city"]
    cca2 = entry["cca2"]
    #map_code += f'map.insert("{iata}", ("{city}", "{cca2}"));\n'
    map_code += f"\"{iata}\" => (\"{city}\", \"{cca2}\"),\n"

print(map_code)
with open('output.rs', 'w', encoding="utf-8") as file:
    file.write(map_code)