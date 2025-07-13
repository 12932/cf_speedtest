import requests

r = requests.get("https://speed.cloudflare.com/locations")
locs_json = r.json()

sorted_data = sorted(locs_json, key=lambda x: x['cca2'], reverse=False)

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