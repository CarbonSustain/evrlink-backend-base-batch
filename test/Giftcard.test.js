const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("NFTGiftMarketplace", function () {
  let marketplace, mockUSDC;
  let owner, addr1, addr2;

  beforeEach(async () => {
    [owner, addr1, addr2] = await ethers.getSigners();

    const MockUSDC = await ethers.getContractFactory("MockUSDC");
    mockUSDC = await MockUSDC.deploy();
    await mockUSDC.waitForDeployment();

    const NFTGiftMarketplace = await ethers.getContractFactory(
      "NFTGiftMarketplace"
    );
    marketplace = await NFTGiftMarketplace.deploy(
      owner.address,
      owner.address,
      owner.address,
      mockUSDC.target
    );
    await marketplace.waitForDeployment();

    await mockUSDC.transfer(addr1.address, ethers.parseUnits("100", 6));
  });

  describe("Backgrounds", () => {
    it("should mint a background", async () => {
      await expect(
        marketplace
          .connect(addr1)
          .mintBackground("ipfs://img1", "Nature", 1200000)
      )
        .to.emit(marketplace, "BackgroundMinted")
        .withArgs(1, addr1.address, "ipfs://img1", "Nature", 1200000);
    });

    it("should fail to mint duplicate background URI", async () => {
      await marketplace
        .connect(addr1)
        .mintBackground("ipfs://img1", "Nature", 1200000);
      await expect(
        marketplace
          .connect(addr1)
          .mintBackground("ipfs://img1", "Nature", 1200000)
      ).to.be.revertedWith("This background has already been minted");
    });
  });

  describe("GiftCard with USDC", () => {
    beforeEach(async () => {
      await marketplace
        .connect(addr1)
        .mintBackground("ipfs://img1", "Nature", 1200000);
    });

    it("should create a gift card", async () => {
      const platformFee = 1100000;
      const climateFee = 11000;
      const taxFee = 0;
      const total = 1200000 + platformFee + taxFee + climateFee;

      await mockUSDC.connect(addr1).approve(marketplace.target, total);
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithUSDC(
            [1],
            "Happy Birthday",
            1200000,
            taxFee,
            climateFee,
            platformFee
          )
      )
        .to.emit(marketplace, "GiftCardCreated")
        .withArgs(1, addr1.address, total, [1]);
    });

    it("should fail if background ID is invalid", async () => {
      await mockUSDC.connect(addr1).approve(marketplace.target, 2000000);
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithUSDC([999], "Invalid BG", 1000, 0, 0, 0)
      ).to.be.revertedWith("ERC721: invalid token ID"); // or your custom revert if implemented
    });

    it("should fail with empty background list", async () => {
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithUSDC([], "Empty", 1000, 0, 0, 0)
      ).to.be.revertedWith("No backgrounds selected");
    });

    it("should fail with insufficient USDC approval", async () => {
      await mockUSDC.connect(addr1).approve(marketplace.target, 1);
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithUSDC([1], "Msg", 1000, 0, 0, 0)
      ).to.be.revertedWith("ERC20: insufficient allowance");
    });
  });

  describe("GiftCard with ETH", () => {
    beforeEach(async () => {
      await marketplace
        .connect(addr1)
        .mintBackground("ipfs://img2", "Abstract", 1000);
    });

    it("should create gift card with ETH", async () => {
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithETH([1], [1000], "ETH Msg", 1000, 100, 100, 100, {
            value: 1300,
          })
      )
        .to.emit(marketplace, "GiftCardCreated")
        .withArgs(1, addr1.address, 1300, [1]);
    });

    it("should fail if ETH sent is too low", async () => {
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithETH([1], [1000], "Fail Msg", 1000, 100, 100, 100, {
            value: 100,
          })
      ).to.be.revertedWith("Insufficient ETH sent");
    });

    it("should fail if arrays mismatch", async () => {
      await expect(
        marketplace
          .connect(addr1)
          .createGiftCardWithETH([1], [1000, 2000], "Mismatch", 1000, 0, 0, 0, {
            value: 1000,
          })
      ).to.be.revertedWith("Mismatched array lengths");
    });
  });

  describe("Secrets and Transfers", () => {
    beforeEach(async () => {
      await marketplace
        .connect(addr1)
        .mintBackground("ipfs://img", "Nature", 1200000);
      const platformFee = 1100000;
      const climateFee = 11000;
      const total = 1200000 + platformFee + climateFee;

      await mockUSDC.connect(addr1).approve(marketplace.target, total);
      await marketplace
        .connect(addr1)
        .createGiftCardWithUSDC(
          [1],
          "Gift",
          1200000,
          0,
          climateFee,
          platformFee
        );
    });

    it("should set secret key", async () => {
      await expect(marketplace.connect(addr1).setSecretKey(1, "secret"))
        .to.emit(marketplace, "SecretKeySet")
        .withArgs(1, addr1.address);
    });

    it("should claim gift card with correct secret", async () => {
      await marketplace.connect(addr1).setSecretKey(1, "secret");
      await expect(marketplace.connect(addr2).claimGiftCard(1, "secret"))
        .to.emit(marketplace, "GiftCardClaimed")
        .withArgs(1, addr2.address);
    });

    it("should fail to claim with wrong secret", async () => {
      await marketplace.connect(addr1).setSecretKey(1, "secret");
      await expect(
        marketplace.connect(addr2).claimGiftCard(1, "wrong")
      ).to.be.revertedWith("Invalid secret");
    });

    it("should transfer gift card", async () => {
      await expect(
        marketplace.connect(addr1).transferGiftCard(1, addr2.address)
      )
        .to.emit(marketplace, "GiftCardTransferred")
        .withArgs(1, addr1.address, addr2.address);
    });
  });

  describe("Token URI", () => {
    it("should return correct token URI", async () => {
      await marketplace
        .connect(addr1)
        .mintBackground("ipfs://imgX", "Space", 1000);
      expect(await marketplace.tokenURI(1)).to.equal("ipfs://imgX");
    });
  });
});
