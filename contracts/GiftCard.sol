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
        uint128 price;
        string message;
        bytes32 secretHash;
        uint32 backgroundId;
    }

    struct Background {
        address artist;
        string imageURI;
        string category;
        uint128 price;
    }

    mapping(uint32 => GiftCard) public giftCards;
    mapping(uint32 => Background) public backgrounds;
    mapping(string => bool) private mintedURIs;

    address public platformAddress;
    address public climateAddress;
    address public taxAddress;

    // Fixed platform fee in wei (~$1.10 at ETH ~$1800)
    uint128 public constant PLATFORM_FEE_IN_WEI = 611111111111111;

    event BackgroundMinted(uint32 indexed backgroundId, address indexed artist, string imageURI, string category, uint128 price);
    event GiftCardCreated(uint32 indexed giftCardId, address indexed creator, uint128 price, uint32 backgroundId);
    event GiftCardTransferred(uint32 indexed giftCardId, address indexed from, address indexed to);
    event GiftCardClaimed(uint32 indexed giftCardId, address indexed recipient);

    constructor(address _platform, address _climate, address _tax) ERC721("BackgroundNFT", "BGNFT") {
        platformAddress = _platform;
        climateAddress = _climate;
        taxAddress = _tax;
    }

    function mintBackground(string memory imageURI, string memory category, uint128 priceInWei) external {
        require(!mintedURIs[imageURI], "This background has already been minted");

        _backgroundIdCounter.increment();
        uint32 backgroundId = uint32(_backgroundIdCounter.current());

        _safeMint(msg.sender, backgroundId);
        _setTokenURI(backgroundId, imageURI);

        backgrounds[backgroundId] = Background({
            artist: msg.sender,
            imageURI: imageURI,
            category: category,
            price: priceInWei
        });

        mintedURIs[imageURI] = true;

        emit BackgroundMinted(backgroundId, msg.sender, imageURI, category, priceInWei);
    }

    function createGiftCard(uint32 backgroundId, string memory message) external payable {
        require(ownerOf(backgroundId) != address(0), "Background does not exist");

        uint128 backgroundPrice = backgrounds[backgroundId].price;

        // Hardcoded fee percentages: tax = 4%, climate = 1%
        uint128 taxFee = (backgroundPrice * 4) / 100;
        uint128 climateFee = (backgroundPrice * 1) / 100;

        uint128 totalRequired = backgroundPrice + PLATFORM_FEE_IN_WEI + taxFee + climateFee;
        require(msg.value >= totalRequired, "Insufficient ETH sent");

        payable(platformAddress).sendValue(PLATFORM_FEE_IN_WEI);
        payable(taxAddress).sendValue(taxFee);
        payable(climateAddress).sendValue(climateFee);
        payable(backgrounds[backgroundId].artist).sendValue(backgroundPrice);

        _giftCardIdCounter.increment();
        uint32 giftCardId = uint32(_giftCardIdCounter.current());

        giftCards[giftCardId] = GiftCard({
            creator: msg.sender,
            currentOwner: msg.sender,
            price: uint128(msg.value),
            message: message,
            secretHash: 0,
            backgroundId: backgroundId
        });

        emit GiftCardCreated(giftCardId, msg.sender, uint128(msg.value), backgroundId);
    }

    function transferGiftCard(uint32 giftCardId, address recipient) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.currentOwner == msg.sender, "Only the owner can transfer the gift card");
        require(recipient != address(0), "Invalid recipient address");

        giftCard.currentOwner = recipient;

        emit GiftCardTransferred(giftCardId, msg.sender, recipient);
    }

    function setSecretKey(uint32 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.currentOwner == msg.sender, "Only the owner can set the secret key");

        giftCard.secretHash = keccak256(abi.encodePacked(secret));
    }

    function claimGiftCard(uint32 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.secretHash == keccak256(abi.encodePacked(secret)), "Invalid secret");

        giftCard.currentOwner = msg.sender;

        emit GiftCardClaimed(giftCardId, msg.sender);
    }

    function _burn(uint256 tokenId) internal override(ERC721URIStorage) {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId) public view override(ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }
}
