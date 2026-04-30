import argparse
import json
import httpx
import time
import os
import sys

PROJECT_ID = 10882

def get_strings(auth_key, file_id):
    headers = {"Authorization": auth_key}
    url = f"https://paratranz.cn/api/projects/{PROJECT_ID}/strings"
    
    strings_map = {}
    page = 1
    page_size = 800
    
    with httpx.Client(timeout=30.0) as client:
        while True:
            params = {"file": file_id, "page": page, "pageSize": page_size}
            print(f"Fetching page {page} from Paratranz (file_id={file_id})...")
            try:
                resp = client.get(url, headers=headers, params=params)
                resp.raise_for_status()
            except Exception as e:
                print(f"Error fetching strings: {e}")
                if hasattr(e, 'response') and e.response is not None:
                    print(e.response.text)
                sys.exit(1)
            
            data = resp.json()
            results = data.get("results", [])
            for item in results:
                strings_map[item["key"]] = item
                
            if len(results) < page_size:
                break
            page += 1
            time.sleep(0.5)
            
    print(f"Fetched {len(strings_map)} strings from file {file_id}.")
    return strings_map

def update_contexts(auth_key, input_file, strings_map):
    headers = {"Authorization": auth_key}
    url_template = f"https://paratranz.cn/api/projects/{PROJECT_ID}/strings/{{string_id}}"
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Failed to read input file {input_file}: {e}")
        sys.exit(1)
        
    print(f"Loaded {len(data)} items to update.")
    updated_count = 0
    skipped_count = 0
    
    with httpx.Client(timeout=30.0) as client:
        for dict_index, json_item in enumerate(data):
            key = json_item.get("key")
            new_context = json_item.get("context")
            
            if not key or not new_context:
                continue
                
            string_item = strings_map.get(key)
            if not string_item:
                print(f"Warning: Key {key} not found in Paratranz file, skipping.")
                skipped_count += 1
                continue
                
            # If the context is already matching, skip to save requests
            if string_item.get("context") == new_context:
                skipped_count += 1
                continue

            # ParaTranz OpenAPI says PUT /projects/{projectId}/strings/{stringId}
            # requires a StringItem. We provide the essential writable fields.
            payload = {
                "context": new_context
            }
            
            try:
                resp = client.put(url_template.format(string_id=string_item['id']), headers=headers, json=payload)
                resp.raise_for_status()
                print(f"Updated string {string_item['id']} ({key}) [{dict_index+1}/{len(data)}]")
                updated_count += 1
            except Exception as e:
                print(f"Failed to update string {string_item['id']} ({key}): {e}")
                if hasattr(e, 'response') and e.response is not None:
                    print(e.response.text)
                
            # Sleep to prevent rate-limiting (HTTP 429) Wait 0.3 seconds between requests (limit is variable, usually ~10/sec)
            time.sleep(0.3)
            
    print(f"\nDone! Updated {updated_count} strings, skipped {skipped_count} strings.")

def main():
    parser = argparse.ArgumentParser(description="Update Context on Paratranz via API")
    parser.add_argument("-i", "--input", required=True, help="Input JSON file containing 'key' and 'context'")
    parser.add_argument("-f", "--file-id", required=True, type=int, help="Paratranz file ID (e.g. 1453)")
    parser.add_argument("-a", "--auth", help="Paratranz Auth Token (defaults to AUTH_KEY env var)")
    args = parser.parse_args()
    
    auth_key = args.auth or os.environ.get("AUTH_KEY")
    if not auth_key:
        print("Error: Paratranz Auth Token must be provided via -a/--auth or AUTH_KEY environment variable.")
        sys.exit(1)
        
    strings_map = get_strings(auth_key, args.file_id)
    update_contexts(auth_key, args.input, strings_map)

if __name__ == "__main__":
    main()