// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./Base64.sol";

/**
 * @title AuditX Smart Contract Security Badge
 * @author Muvva Akhil Yadav
 * @notice Provides fully on-chain SVG generated security badges based on audited security scores.
 * @dev Inherits standard ERC721 properties with base64 on-chain JSON metadata.
 */
contract AuditBadgeNFT is ERC721, Ownable {
    // ── ERC721 Storage & Events ───────────────────────────────────────────────
    uint256 private _tokenIds;
    address public authorizedAgent;

    struct AuditMetadata {
        string contractName;
        uint8 severityScore; // Mapped out of 100 (e.g. 88 = 8.8)
        string ipfsCid;
        uint256 timestamp;
    }

    mapping(uint256 => AuditMetadata) public tokenAuditData;

    event BadgeMinted(address indexed recipient, uint256 indexed tokenId, string contractName, uint8 score, string ipfsCid);

    modifier onlyAgent() {
        require(msg.sender == authorizedAgent || msg.sender == owner(), "Only authorized agent allowed");
        _;
    }

    constructor() ERC721("AuditX Security Badge", "AUDITX") Ownable(msg.sender) {
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

        _mint(recipient, newTokenId);

        tokenAuditData[newTokenId] = AuditMetadata({
            contractName: contractName,
            severityScore: severityScore,
            ipfsCid: ipfsCid,
            timestamp: block.timestamp
        });

        emit BadgeMinted(recipient, newTokenId, contractName, severityScore, ipfsCid);

        return newTokenId;
    }

    // ── On-chain Base64 Metadata Generator ─────────────────────────────────────
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        _requireOwned(tokenId); // OZ v5 helper function
        
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
            "\"image\": \"data:image/svg+xml;base64,", Base64.encode(bytes(svg)), "\",",
            "\"attributes\": [",
            "{\"trait_type\": \"Target Contract\", \"value\": \"", audit.contractName, "\"},",
            "{\"trait_type\": \"CVSS Score\", \"value\": \"", _formatScore(audit.severityScore), "\"},",
            "{\"trait_type\": \"Grade\", \"value\": \"", badgeGrade, "\"},",
            "{\"trait_type\": \"IPFS Report\", \"value\": \"ipfs://", audit.ipfsCid, "\"},",
            "{\"trait_type\": \"Timestamp\", \"value\": \"", _uintToString(audit.timestamp), "\"}",
            "]}"
        ));

        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
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
}
