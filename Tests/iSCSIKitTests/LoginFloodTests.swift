//
//  LoginFloodTests.swift
//  The login exchange against a target that never finishes it.
//
//  Both cases are pre-authentication, and the process on the receiving end
//  is the root daemon. The state machine is pure — no sockets, no clock — so
//  "does this terminate?" is answerable in microseconds.
//

import Foundation
import Testing
@testable import iSCSIKit

@Suite("Login flooding is refused")
struct LoginFloodTests {

    private func config(chap: CHAP.Credentials? = nil) -> LoginConfig {
        var c = LoginConfig(initiatorName: "iqn.2026-08.com.example:mac",
                            sessionType: .normal,
                            targetName: "iqn.2026-08.com.example:disk0",
                            chap: chap)
        c.desired.offerDigests = true
        return c
    }

    /// B4. The C bit set forever with real payload: `loginTextLimit` must
    /// bound what we *receive*, not only what we send.
    @Test("a target that never clears the C bit is cut off at the login text limit")
    func continuationFloodIsBounded() throws {
        var machine = LoginStateMachine(config: config(), cmdSN: 1)
        var request = machine.start()
        var statSN: UInt32 = 0

        var rounds = 0
        var threw = false
        while rounds < 10_000 {
            rounds += 1
            let resp = continuedResponse(to: request, statSN: statSN, bytes: 1024)
            statSN &+= 1
            do {
                switch try machine.receive(resp) {
                case .send(let next): request = next
                case .success, .redirect: Issue.record("flood should not complete a login")
                }
            } catch {
                threw = true
                break
            }
        }
        #expect(threw, "the initiator must refuse the flood rather than buffer it forever")
        // 8192 / 1024 chunks, plus the round that trips the guard. Pinned so a
        // future change that raises the cap has to say so out loud.
        #expect(rounds <= LoginStateMachine.loginTextLimit / 1024 + 2,
                "cut off after \(rounds) rounds, expected ~9")
    }

    /// The livelock the buffer cap alone does not catch: continuations with an
    /// *empty* data segment never grow the buffer, so nothing trips, and the
    /// exchange spins. `ISCSIConnection` bounds the round count for this; see
    /// `connectionCapsEmptyContinuations`.
    @Test("empty continuations do not grow the buffer, so the round cap is what stops them")
    func emptyContinuationsNeedTheRoundCap() throws {
        var machine = LoginStateMachine(config: config(), cmdSN: 1)
        var request = machine.start()
        var statSN: UInt32 = 0

        // Deliberately more rounds than ISCSIConnection allows, to show the
        // state machine alone will keep going: it is the connection's round cap
        // that ends this, which is why that cap exists.
        let rounds = ISCSIConnection.maxLoginRounds * 4
        var askedForMore = 0
        for _ in 0 ..< rounds {
            let resp = continuedResponse(to: request, statSN: statSN, bytes: 0)
            statSN &+= 1
            switch try machine.receive(resp) {
            case .send(let next):
                request = next
                askedForMore += 1
            case .success, .redirect: Issue.record("empty continuations should not complete a login")
            }
        }
        #expect(askedForMore == rounds,
                "the state machine stopped on its own after \(askedForMore) of \(rounds) rounds")
    }

    /// The connection half of the livelock above: the round cap must end it,
    /// at exactly `maxLoginRounds` round trips and with an error that says so.
    @Test("the connection abandons a login still continuing after maxLoginRounds round trips")
    func connectionCapsEmptyContinuations() async throws {
        let target = EmptyContinuationTarget(hangUpAfter: ISCSIConnection.maxLoginRounds * 4)
        let connection = ISCSIConnection(transport: target, login: config())

        let error = await #expect(throws: ConnectionError.self) {
            _ = try await connection.login()
        }
        guard case .loginFailed(let reason)? = error else {
            Issue.record("expected a login failure, got \(String(describing: error))")
            return
        }
        #expect(reason == .protocolViolation(
            "login did not complete within \(ISCSIConnection.maxLoginRounds) round trips"))
        // Pinned so a change to the cap, or an off-by-one in applying it, has
        // to say so out loud.
        #expect(await target.requests == ISCSIConnection.maxLoginRounds)
    }

    /// The bound must not be so tight that a legitimate multi-chunk login fails:
    /// a response that fills `loginTextLimit` exactly is accepted.
    @Test("a response that spans two chunks and fills the text limit exactly is reassembled")
    func legitimateContinuationStillWorks() throws {
        // CHAP, because only on that path does the decoded AuthMethod decide
        // the outcome: a reassembly that lost or garbled either chunk fails
        // with "target answered AuthMethod=<missing>".
        var machine = LoginStateMachine(
            config: config(chap: CHAP.Credentials(name: "user", secret: "s3cret")), cmdSN: 1)
        let request = machine.start()

        let padKey = "X-com.example.Pad"
        let overhead = TextParameters([(key: padKey, value: ""),
                                       (key: "AuthMethod", value: "CHAP")]).encode().count
        let text = TextParameters([
            (key: padKey, value: String(repeating: "A", count: LoginStateMachine.loginTextLimit - overhead)),
            (key: "AuthMethod", value: "CHAP"),
        ]).encode()
        try #require(text.count == LoginStateMachine.loginTextLimit)
        // Split inside "AuthMethod=CHAP": neither chunk alone names the method.
        let split = text.count - 8

        var first = continuedResponse(to: request, statSN: 0, bytes: 0)
        first.dataSegment = text.prefix(split)
        guard case .send(let ack) = try machine.receive(first) else {
            Issue.record("expected the initiator to ask for the rest")
            return
        }
        #expect(ack.dataSegment.isEmpty && !ack.continued && !ack.transit)

        var last = continuedResponse(to: ack, statSN: 1, bytes: 0)
        last.continued = false
        last.dataSegment = text.suffix(from: split)
        guard case .send(let proposal) = try machine.receive(last) else {
            Issue.record("expected the CHAP algorithm proposal")
            return
        }
        #expect(try TextParameters.decode(proposal.dataSegment)["CHAP_A"] == "5")
    }
}

/// A continued login response carrying `bytes` of filler.
private func continuedResponse(to request: LoginRequestPDU,
                               statSN: UInt32,
                               bytes: Int) -> LoginResponsePDU {
    var resp = LoginResponsePDU()
    resp.transit = false
    resp.continued = true
    resp.currentStage = request.currentStage
    resp.nextStage = request.currentStage
    resp.isid = request.isid
    resp.initiatorTaskTag = request.initiatorTaskTag
    resp.statSN = statSN
    resp.expCmdSN = request.cmdSN
    resp.maxCmdSN = request.cmdSN &+ 32
    resp.dataSegment = Data(repeating: 0x41, count: bytes)
    return resp
}

/// A target that answers every login request with an empty C=1 continuation:
/// the livelock `ISCSIConnection.maxLoginRounds` exists for. It hangs up after
/// `hangUpAfter` requests, so an initiator without the cap fails the test with
/// EOF instead of spinning forever.
private actor EmptyContinuationTarget: ConnectionTransport {
    private(set) var requests = 0
    private let hangUpAfter: Int
    private var deframer = PDUDeframer()
    private var replies: [Data] = []
    private var statSN: UInt32 = 0

    init(hangUpAfter: Int) { self.hangUpAfter = hangUpAfter }

    func send(_ data: Data) async throws {
        deframer.append(data)
        while let raw = try deframer.next() {
            guard case .loginRequest(let request) = try AnyPDU.decode(raw) else {
                Issue.record("only login requests belong on the wire before login completes")
                continue
            }
            requests += 1
            guard requests <= hangUpAfter else { continue }
            replies.append(PDUSerializer().serialize(
                continuedResponse(to: request, statSN: statSN, bytes: 0)))
            statSN &+= 1
        }
    }

    func receive() async throws -> Data? {
        replies.isEmpty ? nil : replies.removeFirst()
    }

    func close() async {}
}
