import json
import sqlite3
import collections
import argparse

def main():
    parser = argparse.ArgumentParser(description="Append EVS context to JSON")
    parser.add_argument("-i", "--input", required=True, help="Input JSON file path")
    parser.add_argument("-o", "--output", required=True, help="Output JSON file path")
    args = parser.parse_args()

    conn = sqlite3.connect('example.db')
    cursor = conn.cursor()
    
    # query to get sequence of evs_entries per hgar_file
    query = """
    WITH ordered_evs AS (
        SELECT 
            ee.sentence_key,
            hf.short_name AS evs_name,
            h.name AS hgar_name,
            ROW_NUMBER() OVER (PARTITION BY ee.hgar_file_id ORDER BY ee.id) as evs_index
        FROM evs_entries ee
        JOIN hgar_files hf ON ee.hgar_file_id = hf.id
        JOIN hgars h ON hf.hgar_id = h.id
        WHERE ee.sentence_key IS NOT NULL
    )
    SELECT sentence_key, evs_name, hgar_name, evs_index FROM ordered_evs;
    """
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    mapping = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(list)))
    for sentence_key, evs_name, hgar_name, evs_index in rows:
        mapping[sentence_key][hgar_name][evs_name].append(evs_index)
    
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {args.input}")
        return
        
    output_data = []
    for item in data:
        key = item.get('key')
        context = item.get('context', '')
        if key in mapping:
            sources_lines = []
            for hgar_name, evs_dict in mapping[key].items():
                sources_lines.append(f"- {hgar_name}")
                for evs_name, indices in evs_dict.items():
                    indices_str = ", ".join(map(str, sorted(indices)))
                    sources_lines.append(f"  - {evs_name}: 第 {indices_str} 条")
            
            sources_str = "\n".join(sources_lines)
            if context:
                context = context + "\n\n=== EVS 来源 ===\n" + sources_str
            else:
                context = "=== EVS 来源 ===\n" + sources_str
                
        output_data.append({
            "key": key,
            "context": context
        })
                
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        
    print(f"Success! Processed {len(data)} items and saved to {args.output}")

if __name__ == "__main__":
    main()