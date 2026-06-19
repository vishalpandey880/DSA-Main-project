#include <iomanip>   
#include <iostream> 
#include <limits>  
#include <stack>    
#include <string>   
#include <vector>    
using namespace std;

// Class to store configuration details
class Configuration {
public:
  int version;
  string firewallRule;
  string accessControl;
  string securityPolicy;
  string status;

  // Constructor
  Configuration(int v, string fw, string ac, string sp, string st)
      : version(v), firewallRule(fw), accessControl(ac),
        securityPolicy(sp), status(st) {}
};

// Class to store attack/incident information
class Incident {
public:
  int id;
  string threatType;
  string status;
  string recoveryStatus;

  // Constructor
  Incident(int i, string t)
      : id(i), threatType(t),
        status("Detected"),
        recoveryStatus("Pending") {}
};

class CyberSecurityRecoverySystem {
private:

  // Stack stores configuration backups (LIFO)
  stack<Configuration> configStack;

  // Stores all versions of configurations
  vector<Configuration> versionHistory;

  // Stores all detected incidents
  vector<Incident> incidents;

  // Counters and analytics variables
  int versionNo = 1;
  int incidentNo = 1;
  int totalAttacks = 0;
  int successfulRecoveries = 0;
  int failedRecoveries = 0;
  int downtimeMinutes = 0;

  // Boolean variable for service status
  bool serviceAvailable = true;

public:

  // Save current configuration into stack
  void saveCurrentConfiguration() {

    string fw, ac, sp;

    // Clear input buffer
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    cout << "\n--- Save Current Configuration ---\n";

    // Take configuration details from user
    cout << "Enter current firewall rule: ";
    getline(cin, fw);

    cout << "Enter access control policy: ";
    getline(cin, ac);

    cout << "Enter security policy: ";
    getline(cin, sp);

    // Create configuration object
    Configuration config(versionNo++, fw, ac, sp,
                         "Secure Backup");

    // Push configuration into stack
    configStack.push(config);

    // Store in history
    versionHistory.push_back(config);

    cout << "\n[SUCCESS] Configuration saved.\n";
  }

  // Apply new security policy
  void applyNewSecurityPolicy() {

    // Check if backup exists
    if (configStack.empty()) {
      cout << "\n[ERROR] Save configuration first.\n";
      return;
    }

    string fw, ac, sp;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    cout << "\n--- Apply New Security Policy ---\n";

    getline(cin, fw);
    getline(cin, ac);
    getline(cin, sp);

    // Create new configuration
    Configuration newConfig(versionNo++, fw, ac, sp,
                            "New Policy Applied");

    // Push into stack
    configStack.push(newConfig);

    // Save into history
    versionHistory.push_back(newConfig);

    cout << "\n[SUCCESS] Policy applied.\n";
  }

  // Detect attack or system failure
  void detectAttackOrFailure() {

    string threat;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    cout << "\n--- Detect Attack ---\n";

    getline(cin, threat);

    // Create new incident
    Incident incident(incidentNo++, threat);

    incidents.push_back(incident);

    totalAttacks++;

    // System becomes offline
    serviceAvailable = false;

    // Increase downtime
    downtimeMinutes += 5;

    cout << "\n[WARNING] Attack detected.\n";
  }

  // Rollback to previous secure configuration
  void automatedRollback() {

    // Need at least 2 versions
    if (configStack.size() < 2) {

      failedRecoveries++;

      if (!incidents.empty()) {
        incidents.back().status = "Unresolved";
        incidents.back().recoveryStatus = "Failed";
      }

      cout << "\n[ERROR] Rollback failed.\n";
      return;
    }

    // Remove latest unsafe configuration
    Configuration unsafeConfig = configStack.top();
    configStack.pop();

    // Restore previous secure version
    Configuration restoredConfig =
        configStack.top();

    successfulRecoveries++;

    // Service becomes online again
    serviceAvailable = true;

    if (!incidents.empty()) {
      incidents.back().status = "Resolved";
      incidents.back().recoveryStatus =
          "Rollback Successful";
    }

    cout << "\n[SUCCESS] Rollback completed.\n";
  }

  // View current active configuration
  void viewLatestConfiguration() {

    if (configStack.empty()) {
      cout << "\nNo configuration available.\n";
      return;
    }

    // Peek operation
    Configuration latest = configStack.top();

    cout << "Version: "
         << latest.version << endl;
  }

  // Show all saved versions
  void showVersionHistory() {

    for (const auto &config : versionHistory) {

      cout << "Version: "
           << config.version << endl;
    }
  }

  // Show incident and recovery details
  void securityRecoveryDashboard() {

    cout << "\n===== Dashboard =====\n";

    for (const auto &incident : incidents) {

      cout << "Threat: "
           << incident.threatType << endl;

      cout << "Status: "
           << incident.status << endl;
    }
  }

  // Analytics module
  void securityAnalyticsModule() {

    cout << "Total Attacks: "
         << totalAttacks << endl;

    cout << "Successful Recoveries: "
         << successfulRecoveries << endl;

    // Calculate recovery percentage
    if (totalAttacks > 0) {

      double rate =
          (double)successfulRecoveries /
          totalAttacks * 100;

      cout << "Recovery Rate: "
           << fixed << setprecision(2)
           << rate << "%" << endl;
    }
  }

  // Business continuity report
  void businessContinuitySystem() {

    cout << "Downtime: "
         << downtimeMinutes
         << " minutes\n";

    // Ternary operator
    cout << "Service Status: "
         << (serviceAvailable
             ? "ONLINE"
             : "OFFLINE")
         << endl;
  }

  // Complexity analysis
  void performanceAnalysis() {

    cout << "Push  -> O(1)\n";
    cout << "Pop   -> O(1)\n";
    cout << "Peek  -> O(1)\n";
    cout << "Vector Scan -> O(N)\n";
  }

  // Show project workflow
  void showWorkflow() {

    cout << "1. Save Configuration\n";
    cout << "2. Apply Policy\n";
    cout << "3. Detect Attack\n";
    cout << "4. Rollback\n";
    cout << "5. Restore System\n";
  }
};