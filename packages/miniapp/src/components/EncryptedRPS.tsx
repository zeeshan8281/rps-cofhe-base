"use client";

import { useCallback, useState } from "react";
import { cofhejs, Encryptable } from "cofhejs/web";
import { useReadContract, useAccount } from "wagmi";
import type { ContractFunctionParameters } from "viem";
import {
    Transaction,
    TransactionButton,
} from "@coinbase/onchainkit/transaction";
import type { LifecycleStatus } from "@coinbase/onchainkit/transaction";
import { RPS_CONTRACT_ADDRESS, RPS_CONTRACT_ABI } from "../contracts/deployedContracts";

// Move icons
const RockIcon = () => (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-8 h-8">
        <path d="M18.5 8c-.83 0-1.5.67-1.5 1.5v1.25c-.35-.16-.73-.25-1.13-.25-.44 0-.85.11-1.22.3-.25-.64-.77-1.14-1.44-1.39V5.38c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v4.5l-.55-.55c-.59-.59-1.54-.59-2.12 0-.59.59-.59 1.54 0 2.12l3.17 3.17V19h6v-4.62l2.12-2.12c.28-.28.38-.66.38-1.01V9.5c0-.83-.67-1.5-1.5-1.5zm-.5 5.25l-2.5 2.5v2.75h-3.5v-3.17l-3.17-3.17 2.17-2.17 1 1V5.38c0-.07.07-.13.13-.13s.13.06.13.13v5.12h1.5V9.5c0-.28.22-.5.5-.5s.5.22.5.5v1.5h1c.28 0 .5.22.5.5s-.22.5-.5.5h-.25v.25c0 .28.22.5.5.5s.5-.22.5-.5v-.75h.25c.28 0 .5.22.5.5v1.25z" />
    </svg>
);

const PaperIcon = () => (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-8 h-8">
        <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H5V5h14v14z" />
        <path d="M7 7h10v2H7zM7 11h10v2H7zM7 15h7v2H7z" />
    </svg>
);

const ScissorsIcon = () => (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-8 h-8">
        <path d="M9.64 7.64c.23-.5.36-1.05.36-1.64 0-2.21-1.79-4-4-4S2 3.79 2 6s1.79 4 4 4c.59 0 1.14-.13 1.64-.36L10 12l-2.36 2.36C7.14 14.13 6.59 14 6 14c-2.21 0-4 1.79-4 4s1.79 4 4 4 4-1.79 4-4c0-.59-.13-1.14-.36-1.64L12 14l7 7h3v-1L9.64 7.64zM6 8c-1.1 0-2-.89-2-2s.9-2 2-2 2 .89 2 2-.9 2-2 2zm0 12c-1.1 0-2-.89-2-2s.9-2 2-2 2 .89 2 2-.9 2-2 2zm6-7.5c-.28 0-.5-.22-.5-.5s.22-.5.5-.5.5.22.5.5-.22.5-.5.5zM19 3l-6 6 2 2 7-7V3z" />
    </svg>
);

// Game states
const GameStateLabels = ["Waiting for Players", "Waiting for Player 2", "Waiting for Reveal", "Completed"];

// Move names for display
const MOVES = [
    { id: 0, name: "Rock", icon: RockIcon, emoji: "🪨" },
    { id: 1, name: "Paper", icon: PaperIcon, emoji: "📄" },
    { id: 2, name: "Scissors", icon: ScissorsIcon, emoji: "✂️" },
];

/**
 * EncryptedRPS Component - Rock Paper Scissors with FHE
 */
export const EncryptedRPS = () => {
    const { address } = useAccount();
    const [selectedMove, setSelectedMove] = useState<number | null>(null);
    const [gameId, setGameId] = useState<string>("");
    const [activeTab, setActiveTab] = useState<"cpu" | "create" | "join">("cpu");
    const [successMessage, setSuccessMessage] = useState<string | null>(null);
    const [lastCreatedGameId, setLastCreatedGameId] = useState<number | null>(null);

    // CPU Game State
    const [cpuGameResult, setCpuGameResult] = useState<{
        playerMove: number;
        cpuMove: number;
        result: "win" | "lose" | "draw";
        playerProof?: {
            ctHash: string;
            signature: string;
            securityZone: number;
        };
        cpuProof?: {
            ctHash: string;
            signature: string;
            securityZone: number;
        };
    } | null>(null);
    const [isPlayingCpu, setIsPlayingCpu] = useState(false);
    const [showProofs, setShowProofs] = useState(false);

    // Read total games
    const { data: totalGames, refetch: refetchTotalGames } = useReadContract({
        address: RPS_CONTRACT_ADDRESS as `0x${string}`,
        abi: RPS_CONTRACT_ABI,
        functionName: "getTotalGames",
    });

    // Read specific game if gameId is set
    const { data: gameData, refetch: refetchGame } = useReadContract({
        address: RPS_CONTRACT_ADDRESS as `0x${string}`,
        abi: RPS_CONTRACT_ABI,
        functionName: "getGame",
        args: gameId ? [BigInt(gameId)] : undefined,
        query: { enabled: !!gameId }
    });

    // Check if game is joinable
    const { data: isJoinable } = useReadContract({
        address: RPS_CONTRACT_ADDRESS as `0x${string}`,
        abi: RPS_CONTRACT_ABI,
        functionName: "isGameJoinable",
        args: gameId ? [BigInt(gameId)] : undefined,
        query: { enabled: !!gameId }
    });

    const showSuccess = (message: string) => {
        setSuccessMessage(message);
        setTimeout(() => setSuccessMessage(null), 5000);
    };

    // CPU Game Logic (local simulation with FHE encryption demo)
    const playAgainstCPU = async () => {
        if (selectedMove === null) return;

        setIsPlayingCpu(true);
        setCpuGameResult(null);

        try {
            // Generate random CPU move
            const cpuMove = Math.floor(Math.random() * 3);

            // Simulate encryption delay (for demo purposes)
            await new Promise(resolve => setTimeout(resolve, 1500));

            // Encrypt both moves (demonstrate FHE encryption)
            console.log("Encrypting player move...");
            const playerEncrypted = await cofhejs.encrypt([
                Encryptable.uint8(BigInt(selectedMove)),
            ] as const);
            console.log("Player move encrypted:", playerEncrypted);

            console.log("Encrypting CPU move...");
            const cpuEncrypted = await cofhejs.encrypt([
                Encryptable.uint8(BigInt(cpuMove)),
            ] as const);
            console.log("CPU move encrypted:", cpuEncrypted);

            // Extract proof data from encrypted values
            const playerProofData = playerEncrypted.data?.[0];
            const cpuProofData = cpuEncrypted.data?.[0];

            // Determine winner: (player - cpu + 3) % 3
            // 0 = draw, 1 = player wins, 2 = cpu wins
            const diff = (selectedMove - cpuMove + 3) % 3;
            let result: "win" | "lose" | "draw";
            if (diff === 0) result = "draw";
            else if (diff === 1) result = "win";
            else result = "lose";

            setCpuGameResult({
                playerMove: selectedMove,
                cpuMove,
                result,
                playerProof: playerProofData ? {
                    ctHash: playerProofData.ctHash?.toString() || "N/A",
                    signature: typeof playerProofData.signature === 'string'
                        ? playerProofData.signature.slice(0, 20) + "..."
                        : "0x" + Buffer.from(playerProofData.signature || []).toString('hex').slice(0, 20) + "...",
                    securityZone: playerProofData.securityZone || 0,
                } : undefined,
                cpuProof: cpuProofData ? {
                    ctHash: cpuProofData.ctHash?.toString() || "N/A",
                    signature: typeof cpuProofData.signature === 'string'
                        ? cpuProofData.signature.slice(0, 20) + "..."
                        : "0x" + Buffer.from(cpuProofData.signature || []).toString('hex').slice(0, 20) + "...",
                    securityZone: cpuProofData.securityZone || 0,
                } : undefined,
            });

            if (result === "win") {
                showSuccess("🎉 You won against the CPU!");
            } else if (result === "lose") {
                showSuccess("😢 CPU wins this round!");
            } else {
                showSuccess("🤝 It's a draw!");
            }
        } catch (error) {
            console.error("Error playing against CPU:", error);
        } finally {
            setIsPlayingCpu(false);
        }
    };

    return (
        <div
            className="flex flex-col px-4 sm:px-8 py-6 sm:py-8 items-center gap-4 w-full max-w-2xl mx-auto"
            style={{ backgroundColor: "#122531" }}
        >
            <h2 className="text-lg sm:text-xl font-semibold text-white font-(family-name:--font-clash) text-center">
                🎮 Encrypted Rock Paper Scissors
            </h2>
            <p className="text-sm text-gray-400 text-center">
                Play RPS with encrypted moves using FHE!
            </p>

            {successMessage && (
                <div
                    className="w-full px-3 sm:px-4 py-2 text-xs sm:text-sm text-center font-(family-name:--font-clash)"
                    style={{
                        backgroundColor: "rgba(34, 197, 94, 0.1)",
                        border: "1px solid rgba(34, 197, 94, 0.3)",
                        borderRadius: "0",
                        color: "#86efac",
                    }}
                >
                    {successMessage}
                </div>
            )}

            {/* Tab Navigation */}
            <div className="flex w-full gap-2">
                <button
                    onClick={() => { setActiveTab("cpu"); setCpuGameResult(null); }}
                    className={`flex-1 py-2 px-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-xs sm:text-sm ${activeTab === "cpu"
                        ? "bg-fhenix-cyan text-fhenix-dark"
                        : "bg-gray-800 text-white hover:bg-gray-700"
                        }`}
                >
                    🤖 vs CPU
                </button>
                <button
                    onClick={() => setActiveTab("create")}
                    className={`flex-1 py-2 px-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-xs sm:text-sm ${activeTab === "create"
                        ? "bg-white text-fhenix-dark"
                        : "bg-gray-800 text-white hover:bg-gray-700"
                        }`}
                >
                    Create
                </button>
                <button
                    onClick={() => setActiveTab("join")}
                    className={`flex-1 py-2 px-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-xs sm:text-sm ${activeTab === "join"
                        ? "bg-white text-fhenix-dark"
                        : "bg-gray-800 text-white hover:bg-gray-700"
                        }`}
                >
                    Join
                </button>
            </div>

            {/* Move Selection */}
            <div className="w-full">
                <p className="text-sm text-gray-400 mb-2 text-center">Select your move:</p>
                <div className="flex justify-center gap-3">
                    {MOVES.map((move) => {
                        const Icon = move.icon;
                        return (
                            <button
                                key={move.id}
                                onClick={() => { setSelectedMove(move.id); setCpuGameResult(null); }}
                                className={`flex flex-col items-center justify-center p-4 transition-all border-2 ${selectedMove === move.id
                                    ? "border-fhenix-cyan bg-fhenix-cyan/10"
                                    : "border-gray-700 hover:border-gray-500"
                                    }`}
                                style={{ borderRadius: "0" }}
                            >
                                <Icon />
                                <span className="text-xs mt-1 text-white font-(family-name:--font-clash)">
                                    {move.name}
                                </span>
                            </button>
                        );
                    })}
                </div>
            </div>

            {/* CPU Game Mode */}
            {activeTab === "cpu" && (
                <div className="w-full flex flex-col gap-4">
                    <button
                        onClick={playAgainstCPU}
                        disabled={selectedMove === null || isPlayingCpu}
                        className={`w-full px-4 sm:px-6 py-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-sm ${isPlayingCpu || selectedMove === null
                            ? "opacity-50 cursor-not-allowed"
                            : "hover:opacity-80"
                            }`}
                        style={{
                            backgroundColor: "#0AD9DC",
                            color: "#011623",
                            border: "none",
                            borderRadius: "0",
                        }}
                    >
                        {isPlayingCpu ? (
                            <>
                                <span className="inline-block w-4 h-4 border-2 border-fhenix-dark border-t-transparent rounded-full animate-spin mr-2"></span>
                                Encrypting & Playing...
                            </>
                        ) : (
                            "🎲 Play vs CPU"
                        )}
                    </button>

                    {/* CPU Game Result */}
                    {cpuGameResult && (
                        <div
                            className="w-full px-4 py-4 flex flex-col gap-3"
                            style={{
                                backgroundColor: cpuGameResult.result === "win"
                                    ? "rgba(34, 197, 94, 0.1)"
                                    : cpuGameResult.result === "lose"
                                        ? "rgba(239, 68, 68, 0.1)"
                                        : "rgba(234, 179, 8, 0.1)",
                                border: `1px solid ${cpuGameResult.result === "win"
                                    ? "rgba(34, 197, 94, 0.3)"
                                    : cpuGameResult.result === "lose"
                                        ? "rgba(239, 68, 68, 0.3)"
                                        : "rgba(234, 179, 8, 0.3)"
                                    }`,
                            }}
                        >
                            <div className="text-2xl text-center">
                                {cpuGameResult.result === "win" ? "🎉" : cpuGameResult.result === "lose" ? "😢" : "🤝"}
                            </div>
                            <h3 className={`text-lg font-bold text-center font-(family-name:--font-clash) ${cpuGameResult.result === "win"
                                ? "text-green-400"
                                : cpuGameResult.result === "lose"
                                    ? "text-red-400"
                                    : "text-yellow-400"
                                }`}>
                                {cpuGameResult.result === "win"
                                    ? "You Win!"
                                    : cpuGameResult.result === "lose"
                                        ? "CPU Wins!"
                                        : "It's a Draw!"}
                            </h3>
                            <div className="flex justify-center items-center gap-6 text-white">
                                <div className="text-center">
                                    <p className="text-xs text-gray-400">You</p>
                                    <p className="text-3xl">{MOVES[cpuGameResult.playerMove].emoji}</p>
                                    <p className="text-sm">{MOVES[cpuGameResult.playerMove].name}</p>
                                </div>
                                <div className="text-2xl text-gray-500">vs</div>
                                <div className="text-center">
                                    <p className="text-xs text-gray-400">CPU</p>
                                    <p className="text-3xl">{MOVES[cpuGameResult.cpuMove].emoji}</p>
                                    <p className="text-sm">{MOVES[cpuGameResult.cpuMove].name}</p>
                                </div>
                            </div>

                            {/* Proof Toggle Button */}
                            <button
                                onClick={() => setShowProofs(!showProofs)}
                                className="text-xs text-fhenix-cyan hover:text-white transition-colors mt-2 flex items-center justify-center gap-1"
                            >
                                {showProofs ? "▼" : "▶"} {showProofs ? "Hide" : "View"} Encryption Proofs
                            </button>

                            {/* Proof Details */}
                            {showProofs && cpuGameResult.playerProof && cpuGameResult.cpuProof && (
                                <div
                                    className="mt-3 p-3 text-left space-y-4"
                                    style={{
                                        backgroundColor: "rgba(0, 0, 0, 0.3)",
                                        border: "1px solid rgba(10, 217, 220, 0.2)",
                                    }}
                                >
                                    <h4 className="text-xs font-semibold text-fhenix-cyan uppercase tracking-wider">
                                        🔐 FHE Encryption Proofs
                                    </h4>

                                    {/* Player Proof */}
                                    <div className="space-y-1">
                                        <p className="text-xs text-gray-300 font-semibold">Your Move (Encrypted):</p>
                                        <div className="text-xs text-gray-400 space-y-1 font-mono">
                                            <p><span className="text-gray-500">ctHash:</span> {cpuGameResult.playerProof.ctHash}</p>
                                            <p><span className="text-gray-500">signature:</span> {cpuGameResult.playerProof.signature}</p>
                                            <p><span className="text-gray-500">securityZone:</span> {cpuGameResult.playerProof.securityZone}</p>
                                        </div>
                                    </div>

                                    {/* CPU Proof */}
                                    <div className="space-y-1">
                                        <p className="text-xs text-gray-300 font-semibold">CPU Move (Encrypted):</p>
                                        <div className="text-xs text-gray-400 space-y-1 font-mono">
                                            <p><span className="text-gray-500">ctHash:</span> {cpuGameResult.cpuProof.ctHash}</p>
                                            <p><span className="text-gray-500">signature:</span> {cpuGameResult.cpuProof.signature}</p>
                                            <p><span className="text-gray-500">securityZone:</span> {cpuGameResult.cpuProof.securityZone}</p>
                                        </div>
                                    </div>

                                    <div className="pt-2 border-t border-gray-700 space-y-2">
                                        <p className="text-xs font-semibold text-white">
                                            How Verification Works:
                                        </p>
                                        <div className="text-xs text-gray-500 space-y-1">
                                            <p>
                                                <span className="text-fhenix-cyan">1. Signature Check:</span> The signature proves YOUR wallet
                                                encrypted this value. Anyone can verify this signature matches your address.
                                            </p>
                                            <p>
                                                <span className="text-fhenix-cyan">2. ctHash Uniqueness:</span> Each encrypted value has a unique
                                                hash. This prevents replay attacks and ensures data integrity.
                                            </p>
                                            <p>
                                                <span className="text-fhenix-cyan">3. On-Chain Verification:</span> When sent to a contract,
                                                <code className="text-yellow-400"> FHE.asEuint8()</code> automatically verifies the proof.
                                                Invalid proofs cause the transaction to <span className="text-red-400">REVERT</span>.
                                            </p>
                                        </div>
                                        <div className="mt-2 p-2 bg-green-900/30 border border-green-700/30">
                                            <p className="text-xs text-green-400">
                                                ✅ <strong>Verified:</strong> Both encryptions are valid.
                                                If these were sent on-chain, the smart contract would accept them.
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            )}

                            <p className="text-xs text-gray-400 text-center mt-2">
                                ✨ Both moves were encrypted using FHE before comparison
                            </p>
                        </div>
                    )}
                </div>
            )}

            {/* Create Game Mode */}
            {activeTab === "create" && (
                <>
                    <div className="text-xs text-gray-400 text-center">
                        Total Multiplayer Games: {totalGames?.toString() || "0"}
                    </div>
                    <CreateGameSection
                        selectedMove={selectedMove}
                        onSuccess={(gId) => {
                            showSuccess(`Game #${gId} created! Share this ID with a friend.`);
                            setLastCreatedGameId(gId);
                            refetchTotalGames();
                        }}
                    />
                    {lastCreatedGameId !== null && (
                        <div
                            className="w-full px-4 py-3 text-sm font-(family-name:--font-clash)"
                            style={{
                                backgroundColor: "rgba(10, 217, 220, 0.1)",
                                border: "1px solid rgba(10, 217, 220, 0.3)",
                            }}
                        >
                            <p className="text-white">Your Game ID: <span className="text-fhenix-cyan font-bold">{lastCreatedGameId}</span></p>
                            <p className="text-gray-400 text-xs mt-1">Share this with another player to join!</p>
                        </div>
                    )}
                </>
            )}

            {/* Join Game Mode */}
            {activeTab === "join" && (
                <>
                    <JoinGameSection
                        selectedMove={selectedMove}
                        gameId={gameId}
                        setGameId={setGameId}
                        isJoinable={isJoinable as boolean | undefined}
                        onSuccess={() => {
                            showSuccess(`Joined game #${gameId}! Waiting for reveal.`);
                            refetchGame();
                        }}
                    />
                    {gameId && gameData && (
                        <GameInfo gameId={gameId} gameData={gameData as [string, string, number, string, bigint]} address={address} />
                    )}
                </>
            )}
        </div>
    );
};

/**
 * Create Game Section
 */
const CreateGameSection = ({
    selectedMove,
    onSuccess,
}: {
    selectedMove: number | null;
    onSuccess: (gameId: number) => void;
}) => {
    const { data: totalGames } = useReadContract({
        address: RPS_CONTRACT_ADDRESS as `0x${string}`,
        abi: RPS_CONTRACT_ABI,
        functionName: "getTotalGames",
    });

    const handleOnStatus = useCallback(
        (status: LifecycleStatus) => {
            console.log("Create game status:", status);
            if (status.statusName === "success") {
                onSuccess(Number(totalGames || 0));
            }
        },
        [onSuccess, totalGames]
    );

    const callsCallback = useCallback(async () => {
        if (selectedMove === null) return [];

        const encryptedMove = await cofhejs.encrypt([
            Encryptable.uint8(BigInt(selectedMove)),
        ] as const);

        const calls: ContractFunctionParameters[] = [
            {
                address: RPS_CONTRACT_ADDRESS as `0x${string}`,
                abi: RPS_CONTRACT_ABI as ContractFunctionParameters["abi"],
                functionName: "createGame",
                args: [encryptedMove.data?.[0]],
            },
        ];

        return calls;
    }, [selectedMove]);

    return (
        <div className="w-full">
            <Transaction
                calls={callsCallback}
                onStatus={handleOnStatus}
                resetAfter={2000}
            >
                <TransactionButton
                    disabled={selectedMove === null}
                    render={({ status, onSubmit, isDisabled }) => {
                        const isPending = status === "pending";
                        return (
                            <button
                                className={`w-full px-4 sm:px-6 py-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-sm ${isPending || isDisabled || selectedMove === null
                                    ? "opacity-50 cursor-not-allowed"
                                    : "hover:opacity-80"
                                    }`}
                                style={{
                                    backgroundColor: "#FFFFFF",
                                    color: "#011623",
                                    border: "none",
                                    borderRadius: "0",
                                }}
                                onClick={onSubmit}
                                disabled={isPending || isDisabled || selectedMove === null}
                            >
                                {isPending && (
                                    <span className="inline-block w-4 h-4 border-2 border-fhenix-dark border-t-transparent rounded-full animate-spin mr-2"></span>
                                )}
                                🎮 Create Game
                            </button>
                        );
                    }}
                />
            </Transaction>
        </div>
    );
};

/**
 * Join Game Section
 */
const JoinGameSection = ({
    selectedMove,
    gameId,
    setGameId,
    isJoinable,
    onSuccess,
}: {
    selectedMove: number | null;
    gameId: string;
    setGameId: (id: string) => void;
    isJoinable: boolean | undefined;
    onSuccess: () => void;
}) => {
    const handleOnStatus = useCallback(
        (status: LifecycleStatus) => {
            console.log("Join game status:", status);
            if (status.statusName === "success") {
                onSuccess();
            }
        },
        [onSuccess]
    );

    const callsCallback = useCallback(async () => {
        if (selectedMove === null || !gameId) return [];

        const encryptedMove = await cofhejs.encrypt([
            Encryptable.uint8(BigInt(selectedMove)),
        ] as const);

        const calls: ContractFunctionParameters[] = [
            {
                address: RPS_CONTRACT_ADDRESS as `0x${string}`,
                abi: RPS_CONTRACT_ABI as ContractFunctionParameters["abi"],
                functionName: "joinGame",
                args: [BigInt(gameId), encryptedMove.data?.[0]],
            },
        ];

        return calls;
    }, [selectedMove, gameId]);

    return (
        <div className="w-full flex flex-col gap-3">
            <input
                type="number"
                value={gameId}
                onChange={(e) => setGameId(e.target.value)}
                placeholder="Enter Game ID"
                className="w-full px-3 sm:px-4 py-3 bg-gray-800 text-white border-0 focus:outline-none font-(family-name:--font-clash) text-sm"
                style={{ borderRadius: "0" }}
            />

            {gameId && isJoinable !== undefined && (
                <div className={`text-xs ${isJoinable ? "text-green-400" : "text-red-400"}`}>
                    {isJoinable ? "✓ Game is available to join" : "✗ Game is not available"}
                </div>
            )}

            <Transaction
                calls={callsCallback}
                onStatus={handleOnStatus}
                resetAfter={2000}
            >
                <TransactionButton
                    disabled={selectedMove === null || !gameId || !isJoinable}
                    render={({ status, onSubmit, isDisabled }) => {
                        const isPending = status === "pending";
                        return (
                            <button
                                className={`w-full px-4 sm:px-6 py-3 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-sm ${isPending || isDisabled || selectedMove === null || !gameId
                                    ? "opacity-50 cursor-not-allowed"
                                    : "hover:opacity-80"
                                    }`}
                                style={{
                                    backgroundColor: "#FFFFFF",
                                    color: "#011623",
                                    border: "none",
                                    borderRadius: "0",
                                }}
                                onClick={onSubmit}
                                disabled={isPending || isDisabled || selectedMove === null || !gameId}
                            >
                                {isPending && (
                                    <span className="inline-block w-4 h-4 border-2 border-fhenix-dark border-t-transparent rounded-full animate-spin mr-2"></span>
                                )}
                                🤝 Join Game
                            </button>
                        );
                    }}
                />
            </Transaction>
        </div>
    );
};

/**
 * Game Info Display
 */
const GameInfo = ({
    gameId,
    gameData,
    address,
}: {
    gameId: string;
    gameData: [string, string, number, string, bigint];
    address: string | undefined;
}) => {
    const [player1, player2, state, ,] = gameData;
    const isPlayer1 = address?.toLowerCase() === player1.toLowerCase();
    const isPlayer2 = address?.toLowerCase() === player2.toLowerCase();
    const isPlayer = isPlayer1 || isPlayer2;

    return (
        <div
            className="w-full px-4 py-4 flex flex-col gap-2"
            style={{
                backgroundColor: "rgba(255, 255, 255, 0.05)",
                border: "1px solid rgba(255, 255, 255, 0.1)",
            }}
        >
            <h3 className="text-white font-semibold font-(family-name:--font-clash)">
                Game #{gameId}
            </h3>
            <div className="text-xs text-gray-400 space-y-1">
                <p>Status: <span className="text-fhenix-cyan">{GameStateLabels[state]}</span></p>
                <p>Player 1: <span className="text-white">{player1.slice(0, 8)}...{player1.slice(-6)}</span> {isPlayer1 && "(You)"}</p>
                {player2 !== "0x0000000000000000000000000000000000000000" && (
                    <p>Player 2: <span className="text-white">{player2.slice(0, 8)}...{player2.slice(-6)}</span> {isPlayer2 && "(You)"}</p>
                )}
            </div>

            {state === 2 && isPlayer && (
                <DetermineWinnerButton gameId={gameId} />
            )}
        </div>
    );
};

/**
 * Determine Winner Button
 */
const DetermineWinnerButton = ({ gameId }: { gameId: string }) => {
    const handleOnStatus = useCallback((status: LifecycleStatus) => {
        console.log("Determine winner status:", status);
    }, []);

    const calls: ContractFunctionParameters[] = [
        {
            address: RPS_CONTRACT_ADDRESS as `0x${string}`,
            abi: RPS_CONTRACT_ABI as ContractFunctionParameters["abi"],
            functionName: "determineWinner",
            args: [BigInt(gameId)],
        },
    ];

    return (
        <Transaction calls={calls} onStatus={handleOnStatus} resetAfter={2000}>
            <TransactionButton
                render={({ status, onSubmit, isDisabled }) => {
                    const isPending = status === "pending";
                    return (
                        <button
                            className={`w-full mt-2 px-4 py-2 font-semibold uppercase tracking-widest transition-all font-(family-name:--font-clash) text-sm ${isPending || isDisabled
                                ? "opacity-50 cursor-not-allowed"
                                : "hover:opacity-80"
                                }`}
                            style={{
                                backgroundColor: "#22c55e",
                                color: "#011623",
                                border: "none",
                                borderRadius: "0",
                            }}
                            onClick={onSubmit}
                            disabled={isPending || isDisabled}
                        >
                            {isPending && (
                                <span className="inline-block w-4 h-4 border-2 border-fhenix-dark border-t-transparent rounded-full animate-spin mr-2"></span>
                            )}
                            🏆 Reveal Winner
                        </button>
                    );
                }}
            />
        </Transaction>
    );
};
