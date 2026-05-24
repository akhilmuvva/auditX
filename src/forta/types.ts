// Forta alert as returned by GraphQL API
export interface FortaAlert {
  alertId:     string
  name:        string
  description: string
  severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  createdAt:   string
  source: {
    bot: {
      id:   string
      name: string
    }
    transactionHash: string
    block: {
      number:    number
      timestamp: string
      chainId:   number
    }
  }
  addresses:  string[]
  metadata:   Record<string, string>
}

// A generated Forta detection bot
export interface GeneratedBot {
  sourceCode:  string        // complete bot JS source
  botName:     string        // human readable name
  description: string        // what it detects
  rules:       BotRule[]     // detection rules inside
  contractAddress?: string   // deployed contract being monitored
  generatedAt: number        // unix timestamp
}

export interface BotRule {
  ruleId:      string        // e.g. "REENTRANCY-WATCH-001"
  description: string
  severity:    string
  triggerOn:   string        // event/function being watched
}

// Result of querying Forta for a contract
export interface ContractMonitorStatus {
  contractAddress:  string
  chainId:          number
  totalAlerts:      number
  alertsBySeverity: Record<string, number>
  lastAlertAt:      string | null
  botIds:           string[]
  recentAlerts:     FortaAlert[]
  riskScore:        number    // 0-100 calculated from alerts
  monitoredSince:   number    // unix timestamp
}

// Mapping from AuditX finding types to Forta detection patterns
export interface FindingToFortaMapping {
  auditxFindingType: string   // e.g. "reentrancy-eth"
  fortaRuleId:       string   // e.g. "REENTRANCY-WATCH-001"
  fortaBotTemplate:  string   // bot template key
  severity:          string
  description:       string
  triggerCondition:  string
}

export interface FortaQueryOptions {
  addresses?:   string[]
  botIds?:      string[]
  severities?:  string[]
  chainIds?:    number[]
  startDate?:   string
  limit?:       number
}
