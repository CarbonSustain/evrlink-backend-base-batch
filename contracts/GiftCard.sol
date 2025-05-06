// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Address.sol";

contract NFTGiftMarketplace is ERC721URIStorage, Ownable {
    using Counters for Counters.Counter;
    using Address for address payable;

    Counters.Counter private _backgroundIdCounter;
    Counters.Counter private _giftCardIdCounter;

    struct GiftCard {
        address creator;
        address currentOwner;
        uint256 price;
        string message;
        bytes32 secretHash;
        uint256 backgroundId; // Reference to the background NFT
        bool isClaimable; // Indicates if the gift card is claimable
    }

    struct Background {
        address artist;
        string imageURI;
        string category; // New field for category
        uint256 usageCount;
    }

    mapping(uint256 => GiftCard) public giftCards; // Gift cards are stored in the contract
    mapping(uint256 => Background) public backgrounds; // Background NFTs
    mapping(bytes32 => bool) private hashUsed;
    mapping(string => bool) private mintedURIs; // Track minted image URIs

    event BackgroundMinted(uint256 indexed backgroundId, address indexed artist, string imageURI, string category);
    event GiftCardCreated(uint256 indexed giftCardId, address indexed creator, uint256 price, uint256 backgroundId);
    event GiftCardPurchased(uint256 indexed giftCardId, address indexed buyer, string message);
    event GiftCardTransferred(uint256 indexed giftCardId, address indexed from, address indexed to);
    event GiftCardClaimed(uint256 indexed giftCardId, address indexed recipient);

    constructor() ERC721("BackgroundNFT", "BGNFT") {}

    // Function to mint a background as an NFT with a category
    function mintBackground(string memory imageURI, string memory category) external {
        require(!mintedURIs[imageURI], "This background has already been minted");

        _backgroundIdCounter.increment();
        uint256 backgroundId = _backgroundIdCounter.current();

        _safeMint(msg.sender, backgroundId);
        _setTokenURI(backgroundId, imageURI);

        backgrounds[backgroundId] = Background({
            artist: msg.sender,
            imageURI: imageURI,
            category: category, // Assign the category
            usageCount: 0
        });

        mintedURIs[imageURI] = true; // Mark this URI as minted

        emit BackgroundMinted(backgroundId, msg.sender, imageURI, category);
    }

    // Function to create a gift card using a background NFT
    function createGiftCard(
        uint256 backgroundId,
        uint256 price,
        string memory message
    ) external {
        require(ownerOf(backgroundId) != address(0), "Background does not exist");

        _giftCardIdCounter.increment();
        uint256 giftCardId = _giftCardIdCounter.current();

        giftCards[giftCardId] = GiftCard({
            creator: msg.sender,
            currentOwner: msg.sender,
            price: price,
            message: message,
            secretHash: 0,
            backgroundId: backgroundId,
            isClaimable: false
        });

        backgrounds[backgroundId].usageCount++;

        emit GiftCardCreated(giftCardId, msg.sender, price, backgroundId);
    }

    // Option 1: Directly send the gift card to another user's wallet
    function transferGiftCard(uint256 giftCardId, address recipient) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.currentOwner == msg.sender, "Only the owner can transfer the gift card");
        require(recipient != address(0), "Invalid recipient address");

        giftCard.currentOwner = recipient;
        giftCard.isClaimable = false; // Disable claimable mode since it's directly transferred

        emit GiftCardTransferred(giftCardId, msg.sender, recipient);
    }

    // Option 2: Set a secret key for the gift card to make it claimable
    function setSecretKey(uint256 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.currentOwner == msg.sender, "Only the owner can set the secret key");

        bytes32 secretHash = keccak256(abi.encodePacked(secret));
        require(!hashUsed[secretHash], "Secret already used");

        hashUsed[secretHash] = true;
        giftCard.secretHash = secretHash;
        giftCard.isClaimable = true; // Enable claimable mode

        emit GiftCardTransferred(giftCardId, msg.sender, address(0)); // Indicate it's claimable
    }

    // Function to claim a gift card using the secret key
    function claimGiftCard(uint256 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.isClaimable, "Gift card is not claimable");
        require(giftCard.secretHash == keccak256(abi.encodePacked(secret)), "Invalid secret");

        giftCard.currentOwner = msg.sender;
        giftCard.secretHash = 0; // Prevent reuse
        giftCard.isClaimable = false; // Disable claimable mode after claiming

        emit GiftCardClaimed(giftCardId, msg.sender);
    }

    // Function to buy a gift card
    function buyGiftCard(uint256 giftCardId, string memory message) external payable {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(msg.value == giftCard.price, "Incorrect price");

        address payable seller = payable(giftCard.currentOwner);
        uint256 backgroundId = giftCard.backgroundId;
        address payable artist = payable(ownerOf(backgroundId));

        uint256 artistShare = (msg.value * 40) / 100;
        uint256 sellerShare = msg.value - artistShare;

        artist.sendValue(artistShare);
        seller.sendValue(sellerShare);

        giftCard.currentOwner = msg.sender;
        giftCard.message = message;

        emit GiftCardPurchased(giftCardId, msg.sender, message);
    }

    function _burn(uint256 tokenId) internal override(ERC721URIStorage) {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId) public view override(ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }
}