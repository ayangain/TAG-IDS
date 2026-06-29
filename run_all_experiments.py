import subprocess
import time

hosts = [100, 90, 80, 70, 60, 50, 40, 30, 20]
windows = 4

print(f"Starting batch run for {len(hosts)} experiments: {hosts} hosts, {windows} windows each.")
print("The output for each run will be saved in ids_outputs/run_output{hosts}.txt")

for h in hosts:
    print(f"\n{'='*50}")
    print(f"Starting run for {h} hosts...")
    print(f"{'='*50}")
    
    # Provide the host count and window count via stdin
    input_str = f"{h}\n{windows}\n"
    
    start_time = time.time()
    
    try:
        # Use subprocess.run, which waits for the process to finish
        result = subprocess.run(
            ['.venv/bin/python', 'combined_all.py'],
            input=input_str,
            text=True,
            check=True
        )
        elapsed = time.time() - start_time
        print(f"\n[+] Run for {h} hosts completed in {elapsed:.1f} seconds.")
        print(f"    Output saved to ids_outputs/run_output{h}.txt")
    except subprocess.CalledProcessError as e:
        print(f"\n[-] ERROR: Run for {h} hosts failed with exit code {e.returncode}.")
        print("Aborting remaining runs.")
        break
        
print("\nAll experiments finished successfully!")
