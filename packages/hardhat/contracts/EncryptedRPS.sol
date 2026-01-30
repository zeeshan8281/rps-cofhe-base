// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import "@fhenixprotocol/cofhe-contracts/FHE.sol";

/**
 * @title EncryptedRPS
 * @notice On-chain Rock Paper Scissors with encrypted moves using FHE
 * @dev Moves are encrypted: 0 = Rock, 1 = Paper, 2 = Scissors
 */
contract EncryptedRPS {
    // Game states
    enum GameState {
        WaitingForPlayers,
        WaitingForPlayer2,
        WaitingForReveal,
        Completed
    }

    // Game struct
    struct Game {
        address player1;
        address player2;
        euint8 move1;
        euint8 move2;
        GameState state;
        address winner;
        uint256 createdAt;
    }

    // Mapping from game ID to Game
    mapping(uint256 => Game) public games;
    
    // Current game ID counter
    uint256 public gameCounter;

    // Events
    event GameCreated(uint256 indexed gameId, address indexed player1);
    event PlayerJoined(uint256 indexed gameId, address indexed player2);
    event MovePlayed(uint256 indexed gameId, address indexed player);
    event GameCompleted(uint256 indexed gameId, address indexed winner);

    // Encrypted constants for comparison
    euint8 private ROCK;     // 0
    euint8 private PAPER;    // 1
    euint8 private SCISSORS; // 2
    euint8 private THREE;    // 3 (for modulo)
    euint8 private ONE;      // 1 (for calculation)
    euint8 private TWO;      // 2 (for draw result)

    constructor() {
        ROCK = FHE.asEuint8(0);
        PAPER = FHE.asEuint8(1);
        SCISSORS = FHE.asEuint8(2);
        THREE = FHE.asEuint8(3);
        ONE = FHE.asEuint8(1);
        TWO = FHE.asEuint8(2);

        FHE.allowThis(ROCK);
        FHE.allowThis(PAPER);
        FHE.allowThis(SCISSORS);
        FHE.allowThis(THREE);
        FHE.allowThis(ONE);
        FHE.allowThis(TWO);
    }

    /**
     * @notice Create a new game and submit your encrypted move
     * @param encryptedMove Your encrypted move (0=Rock, 1=Paper, 2=Scissors)
     * @return gameId The ID of the created game
     */
    function createGame(InEuint8 memory encryptedMove) external returns (uint256 gameId) {
        gameId = gameCounter++;
        
        euint8 move = FHE.asEuint8(encryptedMove);
        FHE.allowThis(move);
        FHE.allow(move, msg.sender);

        games[gameId] = Game({
            player1: msg.sender,
            player2: address(0),
            move1: move,
            move2: ROCK, // placeholder
            state: GameState.WaitingForPlayer2,
            winner: address(0),
            createdAt: block.timestamp
        });

        emit GameCreated(gameId, msg.sender);
    }

    /**
     * @notice Join an existing game and submit your encrypted move
     * @param gameId The ID of the game to join
     * @param encryptedMove Your encrypted move (0=Rock, 1=Paper, 2=Scissors)
     */
    function joinGame(uint256 gameId, InEuint8 memory encryptedMove) external {
        Game storage game = games[gameId];
        
        require(game.state == GameState.WaitingForPlayer2, "Game not available");
        require(game.player1 != msg.sender, "Cannot play against yourself");

        euint8 move = FHE.asEuint8(encryptedMove);
        FHE.allowThis(move);
        FHE.allow(move, msg.sender);

        game.player2 = msg.sender;
        game.move2 = move;
        game.state = GameState.WaitingForReveal;

        emit PlayerJoined(gameId, msg.sender);
    }

    /**
     * @notice Determine the winner of the game
     * @param gameId The ID of the game
     * @dev Uses FHE comparison to determine winner without revealing moves
     * 
     * Winner logic (move1 - move2 + 3) % 3:
     * - 0 = Draw
     * - 1 = Player 1 wins
     * - 2 = Player 2 wins
     */
    function determineWinner(uint256 gameId) external {
        Game storage game = games[gameId];
        
        require(game.state == GameState.WaitingForReveal, "Game not ready for reveal");
        require(
            msg.sender == game.player1 || msg.sender == game.player2,
            "Only players can reveal"
        );

        // Calculate (move1 - move2 + 3) % 3
        // Since we can't do negative numbers in FHE, we add 3 before subtracting
        euint8 m1PlusThree = FHE.add(game.move1, THREE);
        euint8 diff = FHE.sub(m1PlusThree, game.move2);
        euint8 result = FHE.rem(diff, THREE);

        // Allow both players to decrypt the result
        FHE.allow(result, game.player1);
        FHE.allow(result, game.player2);
        FHE.allowSender(result);

        // Store the result for decryption
        // The frontend will decrypt and interpret:
        // 0 = Draw, 1 = Player1 wins, 2 = Player2 wins
        
        game.state = GameState.Completed;

        // Request decryption of the result
        FHE.decrypt(result);

        emit GameCompleted(gameId, address(0)); // Winner determined off-chain via decryption
    }

    /**
     * @notice Get game details
     * @param gameId The ID of the game
     */
    function getGame(uint256 gameId) external view returns (
        address player1,
        address player2,
        GameState state,
        address winner,
        uint256 createdAt
    ) {
        Game storage game = games[gameId];
        return (
            game.player1,
            game.player2,
            game.state,
            game.winner,
            game.createdAt
        );
    }

    /**
     * @notice Get the encrypted move of a player (only the player can decrypt)
     * @param gameId The ID of the game
     * @param playerNum 1 for player1, 2 for player2
     */
    function getEncryptedMove(uint256 gameId, uint8 playerNum) external view returns (euint8) {
        Game storage game = games[gameId];
        if (playerNum == 1) {
            return game.move1;
        } else {
            return game.move2;
        }
    }

    /**
     * @notice Get the total number of games created
     */
    function getTotalGames() external view returns (uint256) {
        return gameCounter;
    }

    /**
     * @notice Check if a game is joinable
     */
    function isGameJoinable(uint256 gameId) external view returns (bool) {
        return games[gameId].state == GameState.WaitingForPlayer2;
    }
}
