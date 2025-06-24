// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

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
        uint32[] backgroundIds;
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

    IERC20 public usdcToken;

    event BackgroundMinted(uint32 indexed backgroundId, address indexed artist, string imageURI, string category, uint128 price);
    event GiftCardCreated(uint32 indexed giftCardId, address indexed creator, uint128 price, uint32[] backgroundIds);
    event GiftCardTransferred(uint32 indexed giftCardId, address indexed from, address indexed to);
    event GiftCardClaimed(uint32 indexed giftCardId, address indexed recipient);
    event SecretKeySet(uint32 indexed giftCardId, address indexed owner);

    constructor(
        address _platform,
        address _climate,
        address _tax,
        address _usdcToken
    ) ERC721("BackgroundNFT", "BGNFT") {
        platformAddress = _platform;
        climateAddress = _climate;
        taxAddress = _tax;
        usdcToken = IERC20(_usdcToken);
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

    function createGiftCardWithUSDC(
        uint32[] memory backgroundIds,
        string memory message,
        uint128 backgroundTotalPriceUSDC,
        uint128 taxFeeUSDC,
        uint128 climateFeeUSDC,
        uint128 platformFeeUSDC
    ) external {
        require(backgroundIds.length > 0, "No backgrounds selected");

        uint128 totalUSDC = backgroundTotalPriceUSDC + taxFeeUSDC + climateFeeUSDC + platformFeeUSDC;

        require(
            usdcToken.transferFrom(msg.sender, address(this), totalUSDC),
            "USDC transfer to contract failed"
        );

        // Pay each artist proportionally
        for (uint i = 0; i < backgroundIds.length; i++) {
            uint32 id = backgroundIds[i];
            require(ownerOf(id) != address(0), "Invalid background ID");

            uint128 price = backgrounds[id].price;
            require(usdcToken.transfer(backgrounds[id].artist, price), "USDC to artist failed");
        }

        require(usdcToken.transfer(platformAddress, platformFeeUSDC), "USDC to platform failed");
        require(usdcToken.transfer(taxAddress, taxFeeUSDC), "USDC to tax failed");
        require(usdcToken.transfer(climateAddress, climateFeeUSDC), "USDC to climate failed");

        _recordGiftCard(backgroundIds, message, totalUSDC);
    }

    function createGiftCardWithETH(
        uint32[] memory backgroundIds,
        uint128[] memory artNftPricesETH, // <-- change from uint32[] to uint128[]
        string memory message,
        uint128 backgroundTotalPriceETH,
        uint128 taxFeeETH,
        uint128 climateFeeETH,
        uint128 platformFeeETH
    ) external payable {
        require(backgroundIds.length > 0, "No backgrounds selected");
        require(backgroundIds.length == artNftPricesETH.length, "Mismatched array lengths");

        uint256 totalETH = backgroundTotalPriceETH + taxFeeETH + climateFeeETH + platformFeeETH;
        require(msg.value >= totalETH, "Insufficient ETH sent");

        // Pay each artist
        for (uint i = 0; i < backgroundIds.length; i++) {
            uint32 id = backgroundIds[i];
            require(ownerOf(id) != address(0), "Invalid background ID");

            uint128 price = artNftPricesETH[i];
            payable(backgrounds[id].artist).sendValue(price);
        }

        // Send ETH to fee addresses
        payable(platformAddress).sendValue(platformFeeETH);
        payable(taxAddress).sendValue(taxFeeETH);
        payable(climateAddress).sendValue(climateFeeETH);

        _recordGiftCard(backgroundIds, message, uint128(msg.value));
    }




    function _recordGiftCard(uint32[] memory backgroundIds, string memory message, uint128 value) internal {
        _giftCardIdCounter.increment();
        uint32 giftCardId = uint32(_giftCardIdCounter.current());

        giftCards[giftCardId] = GiftCard({
            creator: msg.sender,
            currentOwner: msg.sender,
            price: value,
            message: message,
            secretHash: 0,
            backgroundIds: backgroundIds
        });

        emit GiftCardCreated(giftCardId, msg.sender, value, backgroundIds);
    }

    function setSecretKey(uint32 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        //require(giftCard.currentOwner == msg.sender, "Only owner can set secret");
        giftCard.secretHash = keccak256(abi.encodePacked(secret));
        emit SecretKeySet(giftCardId, msg.sender);
    }

    function claimGiftCard(uint32 giftCardId, string memory secret) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        require(giftCard.secretHash == keccak256(abi.encodePacked(secret)), "Invalid secret");
        giftCard.currentOwner = msg.sender;
        emit GiftCardClaimed(giftCardId, msg.sender);
    }

    function transferGiftCard(uint32 giftCardId, address recipient) external {
        GiftCard storage giftCard = giftCards[giftCardId];
        //require(giftCard.currentOwner == msg.sender, "Only owner can transfer");
        //require(recipient != address(0), "Invalid recipient");
        giftCard.currentOwner = recipient;
        emit GiftCardTransferred(giftCardId, msg.sender, recipient);
    }

    function tokenURI(uint256 tokenId) public view override(ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    function _burn(uint256 tokenId) internal override(ERC721URIStorage) {
        super._burn(tokenId);
    }
}
