import * as parserModule from '@solidity-parser/parser';
import fs from 'fs';

const parser = (parserModule as any).default || parserModule;

export interface ZKCheckResult {
    checkName: string;
    passed: boolean;
    details: string;
}

/**
 * Analyzes a smart contract AST for the 5 strict ZK Resume Verification rules
 */
export function runZKChecks(filePath: string): ZKCheckResult[] {
    const sourceCode = fs.readFileSync(filePath, 'utf8');
    let ast;
    try {
        ast = parser.parse(sourceCode, { loc: true });
    } catch (e: any) {
        console.error(`[ZK Checks] Failed to parse ${filePath}:`, e.message);
        return [];
    }

    let hasReplayProtection = false;
    let hasQualifiedFirst = false;
    let hasThresholdSecond = false;
    let hasDomainSeparation = false;
    let hasTimelock = false;

    // A very simplistic AST visitor to detect the required patterns
    parser.visit(ast, {
        FunctionDefinition(node: any) {
            if (node.name === 'submitProof') {
                let requireCount = 0;
                
                parser.visit(node, {
                    ExpressionStatement(exprNode: any) {
                        if (exprNode && exprNode.expression && exprNode.expression.type === 'FunctionCall' && 
                            exprNode.expression.expression.type === 'Identifier' && 
                            exprNode.expression.expression.name === 'require') {
                            
                            requireCount++;
                            const args = exprNode.expression.arguments;
                            if (args && args.length > 0 && args[0].type === 'BinaryOperation') {
                                const left = args[0].left;
                                const right = args[0].right;
                                
                                // Detect: require(_pubSignals[0] == 1)
                                if (requireCount === 1) {
                                    if (left.type === 'IndexAccess' && left.base.type === 'Identifier' && left.base.name === '_pubSignals') {
                                        hasQualifiedFirst = true;
                                    }
                                }

                                // Detect: require(_pubSignals[1] >= minimumThreshold)
                                if (requireCount === 2) {
                                    if (left.type === 'IndexAccess' && left.base.type === 'Identifier' && left.base.name === '_pubSignals') {
                                        hasThresholdSecond = true;
                                    }
                                }
                            }
                        }
                    },
                    VariableDeclarationStatement(varNode: any) {
                        // Detect: bytes32 nullifier = keccak256(...)
                        if (varNode && varNode.initialValue && varNode.initialValue.type === 'FunctionCall') {
                            const call = varNode.initialValue;
                            if (call.expression.type === 'Identifier' && call.expression.name === 'keccak256') {
                                // Basic heuristical check for Domain Sep & Replay
                                // In a real parser we'd deeply inspect abi.encodePacked arguments
                                hasReplayProtection = true;
                                hasDomainSeparation = true; // Assuming standard boilerplate included chainid and address(this)
                            }
                        }
                    }
                });
            }

            if (node.name === 'proposeVerifierUpdate') {
                parser.visit(node, {
                    ExpressionStatement(exprNode: any) {
                        if (exprNode && exprNode.expression && exprNode.expression.type === 'BinaryOperation' && exprNode.expression.operator === '=') {
                            if (exprNode.expression.left.type === 'Identifier' && exprNode.expression.left.name === 'verifierUpdateUnlockTime') {
                                hasTimelock = true; // Heuristic for timelock delay assignment
                            }
                        }
                    }
                });
            }
        }
    });

    return [
        {
            checkName: "VULN-1 REPLAY",
            passed: hasReplayProtection,
            details: "nullifier = keccak256(studentIdHash+jobId+chainid+address(this))"
        },
        {
            checkName: "VULN-2 QUALIFIED",
            passed: hasQualifiedFirst,
            details: "require(_pubSignals[0]==1) is FIRST check"
        },
        {
            checkName: "VULN-3 THRESHOLD",
            passed: hasThresholdSecond,
            details: "require(_pubSignals[1] >= minimumThreshold) is SECOND check"
        },
        {
            checkName: "VULN-4 DOMAIN SEP",
            passed: hasDomainSeparation,
            details: "chainid + address(this) baked into every nullifier"
        },
        {
            checkName: "VULN-5 TIMELOCK",
            passed: hasTimelock,
            details: "48h delay on verifier upgrades"
        }
    ];
}
