// Demo C2 communication sample with hardcoded server addresses
// This demonstrates string extraction from compiled binaries
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Hardcoded C2 server configurations
const char* PRIMARY_C2_SERVER = "192.168.100.50";
const char* BACKUP_C2_SERVER = "10.0.2.15";
const char* C2_DOMAIN = "malware-c2.evil.com";
const char* C2_SUBDOMAIN = "beacon.command-control.badguys.org";

// Additional IOCs embedded in the binary
const char* C2_USER_AGENT = "Mozilla/5.0 BotNet/1.0";
const char* EXFIL_EMAIL = "stolen-data@evil-corp.com";
const char* C2_PATHS[] = {
    "/api/beacon",
    "/cmd/poll",
    "/data/exfil"
};

int main(int argc, char** argv) {
    printf("Connecting to C2 server...\n");
    
    // Simulate C2 connection attempt (doesn't actually connect)
    char connection_string[256];
    snprintf(connection_string, sizeof(connection_string), 
             "http://%s:8080%s", C2_DOMAIN, C2_PATHS[0]);
    
    // More IOCs in local variables
    char backup_url[] = "https://10.10.10.10:443/malware/update";
    char data_endpoint[] = "ftp://198.51.100.0/dropzone";
    
    printf("Primary: %s\n", PRIMARY_C2_SERVER);
    printf("Backup: %s\n", BACKUP_C2_SERVER);
    printf("Domain: %s\n", C2_DOMAIN);
    printf("URL: %s\n", connection_string);
    
    // Simulate Windows-specific IOCs
    #ifdef _WIN32
    char registry_key[] = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\EvilBot";
    char windows_path[] = "C:\\Windows\\System32\\evil.dll";
    printf("Registry: %s\n", registry_key);
    printf("Path: %s\n", windows_path);
    #else
    // Linux-specific IOCs
    char linux_path[] = "/etc/cron.d/evil-persistence";
    char systemd_unit[] = "/etc/systemd/system/backdoor.service";
    printf("Cron: %s\n", linux_path);
    printf("Service: %s\n", systemd_unit);
    #endif
    
    return 0;
}