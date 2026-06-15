/**
 * @file Cyber.cpp
 * @brief Cybersecurity Incident Recovery System (CIRS)
 * 
 * This system simulates a security configuration rollback and recovery tool.
 * It uses data structures like Stack (for last-in-first-out configuration rollbacks)
 * and Vectors (for chronological version history and incident tracking) to manage 
 * security backups, detect incidents, and restore services to a last-known-secure state.
 * 
 * Data Structures & Complexity:
 * - Stack (std::stack) for configuration rollbacks:
 *   - Push (Save config): O(1)
 *   - Pop (Rollback config): O(1)
 *   - Top (View latest config): O(1)
 * - Vectors (std::vector) for history and tracking:
 *   - Append (Save/Incident log): O(1) amortized
 *   - Traversal (History/Analytics): O(N) where N is the number of records
 */

#include <iostream>
#include <stack>
#include <string>
#include <vector>
#include <limits>
#include <iomanip>

using namespace std;

/**
 * @class Configuration
 * @brief Represents a system security configuration state.
 */
class Configuration {
public:
  int version;             ///< Version identifier
  string firewallRule;     ///< Active firewall configuration rules
  string accessControl;    ///< Access control lists/policies
  string securityPolicy;   ///< Overall security policy parameters
  string status;           ///< State status (e.g., Secure Backup, New Policy Applied)

  /**
   * @brief Constructor for Configuration.
   */
  Configuration(int v, string fw, string ac, string sp, string st)
      : version(v), firewallRule(fw), accessControl(ac), securityPolicy(sp), status(st) {}
};

/**
 * @class Incident
 * @brief Represents a recorded cybersecurity incident/attack.
 */
class Incident {
public:
  int id;                  ///< Auto-incremented incident ID
  string threatType;       ///< Description of the threat (e.g., DDoS, SQL injection)
  string status;           ///< Status of the incident (Detected, Resolved, Unresolved)
  string recoveryStatus;   ///< Detail on how the incident was recovered (Pending, Rollback Successful, Failed)

  /**
   * @brief Constructor for Incident.
   */
  Incident(int i, string t)
      : id(i), threatType(t), status("Detected"), recoveryStatus("Pending") {}
};

/**
 * @class CyberSecurityRecoverySystem
 * @brief Core system managing backups, rollbacks, incident tracking, and metrics.
 */
class CyberSecurityRecoverySystem {
private:
  stack<Configuration> configStack;      ///< LIFO stack storing configurations for rollback
  vector<Configuration> versionHistory;  ///< Chronological history of all configurations
  vector<Incident> incidents;            ///< Vector tracking all security incidents

  int versionNo = 1;                     ///< Version counter
  int incidentNo = 1;                    ///< Incident counter
  int totalAttacks = 0;                  ///< Total attacks detected
  int successfulRecoveries = 0;          ///< Successful rollbacks
  int failedRecoveries = 0;              ///< Failed rollbacks
  int downtimeMinutes = 0;               ///< Accumulated system downtime
  bool serviceAvailable = true;          ///< Flag representing current system availability

public:
  /**
   * @brief Saves the current configuration to the backup stack.
   * Time Complexity: O(1)
   * Space Complexity: O(1) (for a single push)
   */
  void saveCurrentConfiguration() {
    string fw, ac, sp;

    // Clear input buffer safely up to newline
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    
    cout << "\n--- Save Current Configuration ---\n";
    cout << "Enter current firewall rule: ";
    getline(cin, fw);

    cout << "Enter access control policy: ";
    getline(cin, ac);

    cout << "Enter security policy: ";
    getline(cin, sp);

    Configuration config(versionNo++, fw, ac, sp, "Secure Backup");

    configStack.push(config);
    versionHistory.push_back(config);

    cout << "\n[SUCCESS] Current configuration saved successfully.\n";
    cout << "Performance: Stack Push operation performed in O(1) time.\n";
  }

  /**
   * @brief Applies a new configuration policy on top of the stack.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void applyNewSecurityPolicy() {
    if (configStack.empty()) {
      cout << "\n[ERROR] First save current configuration before applying new policy.\n";
      return;
    }

    string fw, ac, sp;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    
    cout << "\n--- Apply New Security Policy ---\n";
    cout << "Enter new firewall rule: ";
    getline(cin, fw);

    cout << "Enter new access control policy: ";
    getline(cin, ac);

    cout << "Enter new security policy: ";
    getline(cin, sp);

    Configuration newConfig(versionNo++, fw, ac, sp, "New Policy Applied");

    configStack.push(newConfig);
    versionHistory.push_back(newConfig);

    cout << "\n[SUCCESS] New security policy applied successfully.\n";
    cout << "Performance: Configuration pushed into stack in O(1) time.\n";
  }

  /**
   * @brief Registers an attack or system failure. Sets system offline.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void detectAttackOrFailure() {
    string threat;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    
    cout << "\n--- Detect Attack / Failure ---\n";
    cout << "Enter detected threat/failure type (e.g., Ransomware, DDoS): ";
    getline(cin, threat);

    Incident incident(incidentNo++, threat);
    incidents.push_back(incident);

    totalAttacks++;
    serviceAvailable = false;
    downtimeMinutes += 5; // Accumulate downtime per incident

    cout << "\n[WARNING] Attack or failure detected.";
    cout << "\n[STATUS] System state: OFFLINE. Recovery engine activated.\n";
  }

  /**
   * @brief Rolls back the latest (unsafe) configuration to the previous secure state.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void automatedRollback() {
    if (configStack.size() < 2) {
      cout << "\n[ERROR] Rollback failed. Previous secure configuration not available.\n";
      failedRecoveries++;

      if (!incidents.empty()) {
        incidents.back().status = "Unresolved";
        incidents.back().recoveryStatus = "Failed";
      }
      return;
    }

    // Pop the unsafe configuration
    Configuration unsafeConfig = configStack.top();
    configStack.pop();

    // The new top is the last-known secure configuration
    Configuration restoredConfig = configStack.top();

    successfulRecoveries++;
    serviceAvailable = true;

    if (!incidents.empty()) {
      incidents.back().status = "Resolved";
      incidents.back().recoveryStatus = "Automated Rollback Successful";
    }

    cout << "\n[SUCCESS] Automated Rollback Recovery Completed.\n";
    cout << "Unsafe configuration removed:\n";
    cout << " - Removed Version: " << unsafeConfig.version << "\n";

    cout << "\nPrevious secure configuration restored:\n";
    cout << " - Version: " << restoredConfig.version << "\n";
    cout << " - Firewall Rule: " << restoredConfig.firewallRule << "\n";
    cout << " - Access Control: " << restoredConfig.accessControl << "\n";
    cout << " - Security Policy: " << restoredConfig.securityPolicy << "\n";

    cout << "\nPerformance: Stack Pop operation performed in O(1) time.\n";
    cout << "[STATUS] System state: ONLINE. Network services resumed.\n";
  }

  /**
   * @brief Peeks at the active configuration top of stack.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void viewLatestConfiguration() {
    if (configStack.empty()) {
      cout << "\n[INFO] No active configuration available.\n";
      return;
    }

    Configuration latest = configStack.top();

    cout << "\n========== Latest Active Configuration ==========\n";
    cout << "Version:         " << latest.version << "\n";
    cout << "Firewall Rule:   " << latest.firewallRule << "\n";
    cout << "Access Control:  " << latest.accessControl << "\n";
    cout << "Security Policy: " << latest.securityPolicy << "\n";
    cout << "Status:          " << latest.status << "\n";
    cout << "-------------------------------------------------\n";
    cout << "Performance: Stack Peek operation performed in O(1) time.\n";
  }

  /**
   * @brief Iterates and prints all version history.
   * Time Complexity: O(N) where N is number of versions in history
   * Space Complexity: O(1)
   */
  void showVersionHistory() {
    cout << "\n========== Configuration Backup History ==========\n";

    if (versionHistory.empty()) {
      cout << "No backup history available.\n";
      return;
    }

    for (const auto &config : versionHistory) {
      cout << "Version:         " << config.version << "\n";
      cout << "Firewall Rule:   " << config.firewallRule << "\n";
      cout << "Access Control:  " << config.accessControl << "\n";
      cout << "Security Policy: " << config.securityPolicy << "\n";
      cout << "Status:          " << config.status << "\n";
      cout << "-------------------------------------------------\n";
    }
  }

  /**
   * @brief Lists incidents and operational recovery status.
   * Time Complexity: O(M) where M is the number of incidents
   * Space Complexity: O(1)
   */
  void securityRecoveryDashboard() {
    cout << "\n========== Security Recovery Dashboard ==========\n";

    cout << "Incident Tracking Log:\n";
    if (incidents.empty()) {
      cout << "  No security incidents recorded.\n";
    } else {
      for (const auto &incident : incidents) {
        cout << "  Incident ID:     " << incident.id << "\n";
        cout << "  Threat Type:     " << incident.threatType << "\n";
        cout << "  Incident Status: " << incident.status << "\n";
        cout << "  Recovery Detail: " << incident.recoveryStatus << "\n";
        cout << "  -------------------------------------\n";
      }
    }

    cout << "\nRecovery Monitoring Stats:\n";
    cout << "  Successful Recoveries: " << successfulRecoveries << "\n";
    cout << "  Failed Recoveries:     " << failedRecoveries << "\n";
  }

  /**
   * @brief Performs statistical analysis on security recovery rates and attack trends.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void securityAnalyticsModule() {
    cout << "\n========== Security Analytics Module ==========\n";

    cout << "Total Attacks Detected: " << totalAttacks << "\n";
    cout << "Successful Recoveries:  " << successfulRecoveries << "\n";
    cout << "Failed Recoveries:      " << failedRecoveries << "\n";

    if (totalAttacks == 0) {
      cout << "Recovery Success Rate:  0.00%\n";
    } else {
      double rate = (double)successfulRecoveries / totalAttacks * 100;
      cout << "Recovery Success Rate:  " << fixed << setprecision(2) << rate << "%\n";
    }

    cout << "Attack Trend Analysis:  ";
    if (totalAttacks == 0) {
      cout << "No attack trend found (Safe State).\n";
    } else if (totalAttacks <= 2) {
      cout << "Low Attack Trend.\n";
    } else if (totalAttacks <= 5) {
      cout << "Medium Attack Trend.\n";
    } else {
      cout << "High Attack Trend (Critical Action Required).\n";
    }
  }

  /**
   * @brief Shows service availability and downtime.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void businessContinuitySystem() {
    cout << "\n========== Business Continuity System ==========\n";

    cout << "Total Downtime:        " << downtimeMinutes << " minutes\n";
    cout << "Service Availability:  " << (serviceAvailable ? "AVAILABLE (Online)" : "UNAVAILABLE (Offline)") << "\n";

    if (successfulRecoveries > 0) {
      cout << "Recovery Impact:       Downtime minimized via automated rollback.\n";
    } else {
      cout << "Recovery Impact:       No successful rollbacks recorded yet.\n";
    }
  }

  /**
   * @brief Outputs complexity information for submission requirements.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void performanceAnalysis() {
    cout << "\n========== Performance Analysis & Complexities ==========\n";
    cout << "  Save Configuration     -> Stack Push -> Time Complexity: O(1) | Space Complexity: O(1)\n";
    cout << "  Restore Configuration  -> Stack Pop  -> Time Complexity: O(1) | Space Complexity: O(1)\n";
    cout << "  View Latest Version    -> Stack Peek -> Time Complexity: O(1) | Space Complexity: O(1)\n";
    cout << "  Configuration History  -> Vector Scan -> Time Complexity: O(N) | Space Complexity: O(1)\n";
    cout << "  Incident Scanning      -> Vector Scan -> Time Complexity: O(M) | Space Complexity: O(1)\n";
  }

  /**
   * @brief Displays System Workflow.
   * Time Complexity: O(1)
   * Space Complexity: O(1)
   */
  void showWorkflow() {
    cout << "\n========== System Workflow ==========\n";
    cout << "  1. Current stable configuration is saved.\n";
    cout << "  2. Configuration is pushed onto the backup LIFO Stack.\n";
    cout << "  3. A new security policy/configuration is applied.\n";
    cout << "  4. Threat/Failure is detected, driving system OFFLINE.\n";
    cout << "  5. Automated rollback recovery engine is triggered.\n";
    cout << "  6. Unsafe configuration is popped from the stack.\n";
    cout << "  7. Previous secure configuration is restored.\n";
    cout << "  8. Services resume ONLINE and system availability is restored.\n";
  }
};

/**
 * @brief Main execution function containing the menu loop.
 */
int main() {
  CyberSecurityRecoverySystem system;
  int choice;

  do {
    cout << "\n=======================================================\n";
    cout << "       Cybersecurity Incident Recovery System (CIRS)    \n";
    cout << "=======================================================\n";
    cout << "  1. Save Current Configuration\n";
    cout << "  2. Apply New Security Policy\n";
    cout << "  3. Detect Attack / Failure\n";
    cout << "  4. Automated Rollback Recovery\n";
    cout << "  5. View Latest Configuration\n";
    cout << "  6. View Configuration Version History\n";
    cout << "  7. Security Recovery Dashboard\n";
    cout << "  8. Security Analytics Module\n";
    cout << "  9. Business Continuity System\n";
    cout << "  10. Performance Analysis\n";
    cout << "  11. Show System Workflow\n";
    cout << "  12. Exit\n";
    cout << "-------------------------------------------------------\n";
    cout << "Enter your choice (1-12): ";
    
    // Read user choice and handle invalid integer inputs
    if (!(cin >> choice)) {
      cout << "\n[ERROR] Invalid input. Please enter a number between 1 and 12.\n";
      cin.clear(); // Clear error flags
      cin.ignore(numeric_limits<streamsize>::max(), '\n'); // Clear buffer
      choice = 0; // Reset choice to keep loop running
      continue;
    }

    switch (choice) {
    case 1:
      system.saveCurrentConfiguration();
      break;

    case 2:
      system.applyNewSecurityPolicy();
      break;

    case 3:
      system.detectAttackOrFailure();
      break;

    case 4:
      system.automatedRollback();
      break;

    case 5:
      system.viewLatestConfiguration();
      break;

    case 6:
      system.showVersionHistory();
      break;

    case 7:
      system.securityRecoveryDashboard();
      break;

    case 8:
      system.securityAnalyticsModule();
      break;

    case 9:
      system.businessContinuitySystem();
      break;

    case 10:
      system.performanceAnalysis();
      break;

    case 11:
      system.showWorkflow();
      break;

    case 12:
      cout << "\nExiting CyberSecurity Recovery System. Goodbye!\n";
      break;

    default:
      cout << "\n[ERROR] Choice out of range. Please choose a number between 1 and 12.\n";
    }

  } while (choice != 12);

  return 0;
}