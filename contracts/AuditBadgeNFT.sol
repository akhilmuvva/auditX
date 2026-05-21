// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AuditX Smart Contract Security Badge
 * @author Muvva Akhil Yadav
 * @notice Provides fully on-chain SVG generated security badges based on audited security scores.
 * @dev Inherits standard ERC721 properties with base64 on-chain JSON metadata.
 */

// Simple OpenZeppelin-compatible ERC-721 base to allow full compilation
interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract AuditBadgeNFT {
    // ── ERC721 Storage & Events ───────────────────────────────────────────────
    string public constant name = "AuditX Security Badge";
    string public constant symbol = "AUDITX";
    
    uint256 private _tokenIds;
    address public owner;
    address public authorizedAgent;

    struct AuditMetadata {
        string contractName;
        uint8 severityScore; // Mapped out of 100 (e.g. 88 = 8.8)
        string ipfsCid;
        uint256 timestamp;
    }

    mapping(uint256 => address) private _owners;
    mapping(address => uint256) private _balances;
    mapping(uint256 => AuditMetadata) public tokenAuditData;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event BadgeMinted(address indexed recipient, uint256 indexed tokenId, string contractName, uint8 score, string ipfsCid);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner allowed");
        _;
    }

    modifier onlyAgent() {
        require(msg.sender == authorizedAgent || msg.sender == owner, "Only authorized agent allowed");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedAgent = msg.sender;
    }

    function setAuthorizedAgent(address agent) external onlyOwner {
        authorizedAgent = agent;
    }

    // ── Core Minting Function ──────────────────────────────────────────────────
    function mintBadge(
        address recipient,
        string calldata contractName,
        uint8 severityScore,
        string calldata ipfsCid
    ) external onlyAgent returns (uint256) {
        require(recipient != address(0), "Cannot mint to zero address");
        require(severityScore < 70, "Severity too high for security badge"); // 7.0 score maximum

        _tokenIds++;
        uint256 newTokenId = _tokenIds;

        _owners[newTokenId] = recipient;
        _balances[recipient]++;

        tokenAuditData[newTokenId] = AuditMetadata({
            contractName: contractName,
            severityScore: severityScore,
            ipfsCid: ipfsCid,
            timestamp: block.timestamp
        });

        emit Transfer(address(0), recipient, newTokenId);
        emit BadgeMinted(recipient, newTokenId, contractName, severityScore, ipfsCid);

        return newTokenId;
    }

    // ── Standard ERC721 View Utilities ─────────────────────────────────────────
    function balanceOf(address account) external view returns (uint256) {
        require(account != address(0), "Zero address query");
        return _balances[account];
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        address tokenOwner = _owners[tokenId];
        require(tokenOwner != address(0), "Query for nonexistent token");
        return tokenOwner;
    }

    // ── On-chain Base64 Metadata Generator ─────────────────────────────────────
    function tokenURI(uint256 tokenId) external view returns (string memory) {
        require(_owners[tokenId] != address(0), "Query for nonexistent token");
        
        AuditMetadata memory audit = tokenAuditData[tokenId];
        
        // Dynamically assign badge properties based on score threshold
        string memory shieldColor = "#10B981"; // Emerald green (Default safe)
        string memory badgeGrade = "EMERALD GUARD";
        
        if (audit.severityScore >= 40) {
            shieldColor = "#F59E0B"; // Amber warning (4.0 - 6.9)
            badgeGrade = "AMBER GUARD";
        }

        // 1. Generate full On-Chain SVG Badge
        string memory svg = string(abi.encodePacked(
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 500' width='100%' height='100%' style='background:#050508;font-family:\"Outfit\",sans-serif;'>",
            "<defs>",
            "<linearGradient id='glow' x1='0%' y1='0%' x2='100%' y2='100%'>",
            "<stop offset='0%' stop-color='", shieldColor, "' stop-opacity='0.4'/>",
            "<stop offset='100%' stop-color='#0a0b10' stop-opacity='0'/>",
            "</linearGradient>",
            "</defs>",
            "<rect width='400' height='500' rx='30' fill='#0a0b10' stroke='rgba(255,255,255,0.08)' stroke-width='1.5'/>",
            "<circle cx='200' cy='200' r='140' fill='url(#glow)' filter='blur(30px)'/>",
            "<polygon points='200,80 320,140 320,300 200,420 80,300 80,140' fill='none' stroke='", shieldColor, "' stroke-width='2' stroke-dasharray='1000' style='filter:drop-shadow(0 0 15px ", shieldColor, ")'/>",
            "<path d='M170 180l20 20 40-40' fill='none' stroke='", shieldColor, "' stroke-width='4' stroke-linecap='round' stroke-linejoin='round'/>",
            "<text x='200' y='270' fill='#ffffff' font-size='22' font-weight='800' text-anchor='middle' letter-spacing='1'>", badgeGrade, "</text>",
            "<text x='200' y='305' fill='rgba(255,255,255,0.6)' font-size='11' font-weight='700' text-anchor='middle' letter-spacing='2.5'>SECURITY CERTIFIED</text>",
            "<text x='200' y='350' fill='#818cf8' font-size='10' font-family='monospace' text-anchor='middle'>CVSS IMPACT: ", _formatScore(audit.severityScore), "</text>",
            "<text x='200' y='450' fill='rgba(255,255,255,0.4)' font-size='9' font-weight='500' text-anchor='middle'>TARGET: ", audit.contractName, "</text>",
            "<text x='200' y='470' fill='rgba(255,255,255,0.25)' font-size='8' font-family='monospace' text-anchor='middle'>CID: ", _substring(audit.ipfsCid, 0, 16), "...</text>",
            "</svg>"
        ));

        // 2. Wrap as standard ERC-721 base64 metadata payload
        string memory json = string(abi.encodePacked(
            "{\"name\": \"AuditX Certificate #", _uintToString(tokenId), "\",",
            "\"description\": \"Fully decentralized on-chain security audit badge proving clean contract compliance.\",",
            "\"image\": \"data:image/svg+xml;base64,", _base64Encode(bytes(svg)), "\",",
            "\"attributes\": [",
            "{\"trait_type\": \"Target Contract\", \"value\": \"", audit.contractName, "\"},",
            "{\"trait_type\": \"CVSS Score\", \"value\": \"", _formatScore(audit.severityScore), "\"},",
            "{\"trait_type\": \"Grade\", \"value\": \"", badgeGrade, "\"},",
            "{\"trait_type\": \"IPFS Report\", \"value\": \"ipfs://", audit.ipfsCid, "\"},",
            "{\"trait_type\": \"Timestamp\", \"value\": \"", _uintToString(audit.timestamp), "\"}",
            "]}"
        ));

        return string(abi.encodePacked("data:application/json;base64,", _base64Encode(bytes(json))));
    }

    // ── Helper Math Functions ──────────────────────────────────────────────────
    function _formatScore(uint8 score) internal pure returns (string memory) {
        if (score == 0) return "0.0";
        uint256 whole = score / 10;
        uint256 decimal = score % 10;
        return string(abi.encodePacked(_uintToString(whole), ".", _uintToString(decimal)));
    }

    function _uintToString(uint256 v) internal pure returns (string memory) {
        if (v == 0) return "0";
        uint256 temp = v;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (v != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(v % 10)));
            v /= 10;
        }
        return string(buffer);
    }

    function _substring(string memory str, uint256 startIndex, uint256 endIndex) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            if (i < strBytes.length) {
                result[i - startIndex] = strBytes[i];
            } else {
                result[i - startIndex] = " ";
            }
        }
        return string(result);
    }

    // ── Pure Solidity Base64 Encoder ───────────────────────────────────────────
    function _base64Encode(bytes memory data) internal pure returns (string memory) {
        string memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        bytes memory tableBytes = bytes(table);
        
        if (data.length == 0) return "";
        
        uint256 encodedLength = 4 * ((data.length + 2) / 3);
        bytes memory result = new bytes(encodedLength + 32); // add buffering padding
        
        uint256 i = 0;
        uint256 j = 0;
        
        for (; i + 3 <= data.length; i += 3) {
            uint256 input = (uint256(uint8(data[i])) << 16) | (uint256(uint8(data[i+1])) << 8) | uint256(uint8(data[i+2]));
            result[j++] = tableBytes[(input >> 18) & 63];
            result[j++] = tableBytes[(input >> 12) & 63];
            result[j++] = tableBytes[(input >> 6) & 63];
            result[j++] = tableBytes[input & 63];
        }
        
        if (data.length - i == 1) {
            uint256 input = uint256(uint8(data[i])) << 16;
            result[j++] = tableBytes[(input >> 18) & 63];
            result[j++] = tableBytes[(input >> 12) & 63];
            result[j++] = "=";
            result[j++] = "=";
        } else if (data.length - i == 2) {
            uint256 input = (uint256(uint8(data[i])) << 16) | (uint256(uint8(data[i+1])) << 8);
            result[j++] = tableBytes[(input >> 18) & 63];
            result[j++] = tableBytes[(input >> 12) & 63];
            result[j++] = tableBytes[(input >> 6) & 63];
            result[j++] = "=";
        }
        
        // Truncate to exact length
        bytes memory finalResult = new bytes(j);
        for (uint256 k = 0; k < j; k++) {
            finalResult[k] = result[k];
        }
        
        return string(finalResult);
    }
}
