// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DNAChain
 * @dev A smart contract for secure DNA data management on blockchain
 * @author DNAChain Team
 */
contract DNAChain {
    
    // Struct to store DNA data information
    struct DNARecord {
        bytes32 dataHash;      // Hash of the DNA data
        address owner;         // Owner of the DNA data
        uint256 timestamp;     // When the data was stored
        bool isVerified;       // Verification status
        string metadata;       // Additional metadata (encrypted)
    }
    
    // Mapping from record ID to DNA record
    mapping(uint256 => DNARecord) public dnaRecords;
    
    // Mapping from owner address to their record IDs
    mapping(address => uint256[]) public ownerRecords;
    
    // Mapping for authorized researchers/institutions
    mapping(address => bool) public authorizedResearchers;
    
    // Events
    event DNADataStored(uint256 indexed recordId, address indexed owner, bytes32 dataHash);
    event DNADataVerified(uint256 indexed recordId, address indexed verifier);
    event ResearcherAuthorized(address indexed researcher, address indexed authorizer);
    event ResearcherRevoked(address indexed researcher, address indexed revoker);
    
    // State variables
    uint256 private nextRecordId;
    address public admin;
    
    // Modifiers
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }
    
    modifier onlyOwner(uint256 _recordId) {
        require(dnaRecords[_recordId].owner == msg.sender, "Only owner can access this record");
        _;
    }
    
    modifier onlyAuthorized() {
        require(authorizedResearchers[msg.sender] || msg.sender == admin, "Not authorized");
        _;
    }
    
    constructor() {
        admin = msg.sender;
        nextRecordId = 1;
    }
    
    /**
     * @dev Core Function 1: Store DNA data hash on blockchain
     * @param _dataHash Hash of the DNA data (computed off-chain)
     * @param _metadata Encrypted metadata associated with the DNA sample
     * @return recordId The unique identifier for this DNA record
     */
    function storeDNAData(bytes32 _dataHash, string memory _metadata) 
        external 
        returns (uint256 recordId) 
    {
        require(_dataHash != bytes32(0), "Invalid data hash");
        
        recordId = nextRecordId++;
        
        dnaRecords[recordId] = DNARecord({
            dataHash: _dataHash,
            owner: msg.sender,
            timestamp: block.timestamp,
            isVerified: false,
            metadata: _metadata
        });
        
        ownerRecords[msg.sender].push(recordId);
        
        emit DNADataStored(recordId, msg.sender, _dataHash);
        
        return recordId;
    }
    
    /**
     * @dev Core Function 2: Retrieve DNA record information
     * @param _recordId The ID of the DNA record to retrieve
     * @return dataHash Hash of the DNA data
     * @return owner Address of the record owner
     * @return timestamp When the record was created
     * @return isVerified Verification status
     * @return metadata Associated metadata
     */
    function getDNARecord(uint256 _recordId) 
        external 
        view 
        onlyOwner(_recordId)
        returns (
            bytes32 dataHash,
            address owner,
            uint256 timestamp,
            bool isVerified,
            string memory metadata
        ) 
    {
        require(_recordId > 0 && _recordId < nextRecordId, "Record does not exist");
        
        DNARecord memory record = dnaRecords[_recordId];
        
        return (
            record.dataHash,
            record.owner,
            record.timestamp,
            record.isVerified,
            record.metadata
        );
    }
    
    /**
     * @dev Core Function 3: Verify DNA data integrity
     * @param _recordId The ID of the DNA record to verify
     * @param _providedHash The hash to verify against stored hash
     * @return isValid True if the provided hash matches the stored hash
     */
    function verifyDNAData(uint256 _recordId, bytes32 _providedHash) 
        external 
        onlyAuthorized
        returns (bool isValid) 
    {
        require(_recordId > 0 && _recordId < nextRecordId, "Record does not exist");
        
        DNARecord storage record = dnaRecords[_recordId];
        isValid = (record.dataHash == _providedHash);
        
        if (isValid && !record.isVerified) {
            record.isVerified = true;
            emit DNADataVerified(_recordId, msg.sender);
        }
        
        return isValid;
    }
    
    /**
     * @dev Authorize a researcher/institution to verify DNA data
     * @param _researcher Address of the researcher to authorize
     */
    function authorizeResearcher(address _researcher) external onlyAdmin {
        require(_researcher != address(0), "Invalid researcher address");
        require(!authorizedResearchers[_researcher], "Researcher already authorized");
        
        authorizedResearchers[_researcher] = true;
        emit ResearcherAuthorized(_researcher, msg.sender);
    }
    
    /**
     * @dev Revoke researcher authorization
     * @param _researcher Address of the researcher to revoke
     */
    function revokeResearcher(address _researcher) external onlyAdmin {
        require(authorizedResearchers[_researcher], "Researcher not authorized");
        
        authorizedResearchers[_researcher] = false;
        emit ResearcherRevoked(_researcher, msg.sender);
    }
    
    /**
     * @dev Get all record IDs owned by an address
     * @param _owner Address of the owner
     * @return Array of record IDs
     */
    function getOwnerRecords(address _owner) external view returns (uint256[] memory) {
        return ownerRecords[_owner];
    }
    
    /**
     * @dev Get total number of DNA records stored
     * @return Total number of records
     */
    function getTotalRecords() external view returns (uint256) {
        return nextRecordId - 1;
    }
}
