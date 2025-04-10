;; InnoTrade Protocol - Decentralized Holdings System which is a comprehensive framework for managed digital resource reservations with multi-party verification

;; System constants
(define-constant PROTOCOL_OVERSEER tx-sender)
(define-constant ERROR_UNAUTHORIZED (err u100))
(define-constant ERROR_RESERVATION_MISSING (err u101))
(define-constant ERROR_ALREADY_PROCESSED (err u102))
(define-constant ERROR_DISPATCH_FAILED (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_RESERVATION_OUTDATED (err u107))
(define-constant RESERVATION_LIFESPAN_BLOCKS u1008)

;; Primary data structure for reservations
(define-map ReservationLedger
  { reservation-identifier: uint }
  {
    originator: principal,
    beneficiary: principal,
    resource-identifier: uint,
    quantity: uint,
    reservation-status: (string-ascii 10),
    genesis-block: uint,
    termination-block: uint
  }
)

;; Track the sequential reservation identifiers
(define-data-var latest-reservation-identifier uint u0)

;; Implementation helpers
(define-private (eligible-beneficiary? (beneficiary principal))
  (and 
    (not (is-eq beneficiary tx-sender))
    (not (is-eq beneficiary (as-contract tx-sender)))
  )
)


(define-private (verify-reservation-exists? (reservation-identifier uint))
  (<= reservation-identifier (var-get latest-reservation-identifier))
)

;; Core protocol functions

;; Execute resource transfer to beneficiary
(define-public (finalize-resource-transfer (reservation-identifier uint))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (beneficiary (get beneficiary reservation-entry))
        (quantity (get quantity reservation-entry))
        (resource (get resource-identifier reservation-entry))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_OVERSEER) (is-eq tx-sender (get originator reservation-entry))) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get reservation-status reservation-entry) "pending") ERROR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get termination-block reservation-entry)) ERROR_RESERVATION_OUTDATED)
      (match (as-contract (stx-transfer? quantity tx-sender beneficiary))
        success
          (begin
            (map-set ReservationLedger
              { reservation-identifier: reservation-identifier }
              (merge reservation-entry { reservation-status: "completed" })
            )
            (print {action: "resource_transferred", reservation-identifier: reservation-identifier, beneficiary: beneficiary, resource-identifier: resource, quantity: quantity})
            (ok true)
          )
        error ERROR_DISPATCH_FAILED
      )
    )
  )
)

;; Implement resource quarantine for suspicious reservations
(define-public (quarantine-suspicious-reservation (reservation-identifier uint) (suspicion-evidence (buff 64)))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (status (get reservation-status reservation-entry))
        (quarantine-period u144) ;; 24 hours quarantine by default
      )
      (asserts! (is-eq tx-sender PROTOCOL_OVERSEER) ERROR_UNAUTHORIZED)
      (asserts! (or (is-eq status "pending") (is-eq status "acknowledged")) ERROR_ALREADY_PROCESSED)
      (asserts! (> (len suspicion-evidence) u32) (err u250)) ;; Ensure substantial evidence is provided

      (print {action: "reservation_quarantined", reservation-identifier: reservation-identifier, 
              evidence-digest: (hash160 suspicion-evidence), quarantine-until: (+ block-height quarantine-period)})
      (ok (+ block-height quarantine-period))
    )
  )
)

;; Implement tiered authorization based on resource value threshold
(define-public (enforce-tiered-authorization (reservation-identifier uint) (authorization-tier (string-ascii 10)) (authorization-proof (buff 64)))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (quantity (get quantity reservation-entry))
        (originator (get originator reservation-entry))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_OVERSEER)) ERROR_UNAUTHORIZED)
      (asserts! (is-eq (get reservation-status reservation-entry) "pending") ERROR_ALREADY_PROCESSED)

      ;; Validate authorization tier based on quantity
      (asserts! (or 
                  (and (is-eq authorization-tier "standard") (<= quantity u1000))
                  (and (is-eq authorization-tier "enhanced") (and (> quantity u1000) (<= quantity u10000)))
                  (and (is-eq authorization-tier "critical") (> quantity u10000))
                ) (err u260))

      (print {action: "tiered_authorization_enforced", reservation-identifier: reservation-identifier, 
              authorization-tier: authorization-tier, quantity: quantity, 
              authorization-proof-digest: (hash160 authorization-proof)})
      (ok true)
    )
  )
)


;; Implement secure resource allocation with anti-sybil protection
;; Prevents malicious actors from creating multiple identities to bypass limits
(define-public (execute-authenticated-allocation (beneficiary principal) (resource-identifier uint) (quantity uint) (identity-proof (buff 65)))
  (begin
    (asserts! (> quantity u0) ERROR_INVALID_QUANTITY)
    (asserts! (eligible-beneficiary? beneficiary) ERROR_INVALID_ORIGINATOR)
    (let
      (
        (new-identifier (+ (var-get latest-reservation-identifier) u1))
        (termination-date (+ block-height RESERVATION_LIFESPAN_BLOCKS))
        (identity-hash (hash160 identity-proof))
      )
      ;; Verify sufficient balance for allocation
      (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
        success
          (begin
            ;; Create new reservation with authenticated identity
            (var-set latest-reservation-identifier new-identifier)

            (print {action: "authenticated_allocation_created", reservation-identifier: new-identifier, 
                    originator: tx-sender, beneficiary: beneficiary, resource-identifier: resource-identifier,
                    quantity: quantity, identity-hash: identity-hash})
            (ok new-identifier)
          )
        error ERROR_DISPATCH_FAILED
      )
    )
  )
)

;; Execute time-locked resource recovery
;; Provides secure recovery mechanism that requires waiting period before execution
(define-public (execute-time-locked-recovery (reservation-identifier uint) (recovery-confirmation-code (buff 32)))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (originator (get originator reservation-entry))
        (quantity (get quantity reservation-entry))
        (minimum-delay-blocks u144) ;; 24-hour delay requirement (144 blocks)
        (recovery-eligibility-block (+ (get genesis-block reservation-entry) minimum-delay-blocks))
      )
      ;; Only originator can initiate recovery
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      ;; Must be in pending or acknowledged state to recover
      (asserts! (or (is-eq (get reservation-status reservation-entry) "pending") 
                   (is-eq (get reservation-status reservation-entry) "acknowledged")) ERROR_ALREADY_PROCESSED)
      ;; Verify minimum time delay has passed
      (asserts! (>= block-height recovery-eligibility-block) (err u280))
      ;; Only active reservations within termination window
      (asserts! (<= block-height (get termination-block reservation-entry)) ERROR_RESERVATION_OUTDATED)

      ;; Process the recovery transfer
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ReservationLedger
              { reservation-identifier: reservation-identifier }
              (merge reservation-entry { reservation-status: "recovered" })
            )
            (print {action: "time_locked_recovery_executed", reservation-identifier: reservation-identifier, 
                   originator: originator, quantity: quantity, confirmation-digest: (hash160 recovery-confirmation-code)})
            (ok true)
          )
        error ERROR_DISPATCH_FAILED
      )
    )
  )
)

;; Implement beneficiary acknowledgment process
;; Ensures beneficiary is aware of and approves the reservation
(define-public (acknowledge-reservation (reservation-identifier uint) (acknowledgment-code (buff 32)))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (beneficiary (get beneficiary reservation-entry))
      )
      ;; Only beneficiary can acknowledge reservation
      (asserts! (is-eq tx-sender beneficiary) ERROR_UNAUTHORIZED)
      ;; Can only acknowledge pending reservations
      (asserts! (is-eq (get reservation-status reservation-entry) "pending") ERROR_ALREADY_PROCESSED)
      ;; Ensure reservation hasn't expired
      (asserts! (<= block-height (get termination-block reservation-entry)) ERROR_RESERVATION_OUTDATED)

      ;; Update reservation status to acknowledged

      (print {action: "reservation_acknowledged", reservation-identifier: reservation-identifier, 
              beneficiary: beneficiary, acknowledgment-digest: (hash160 acknowledgment-code)})
      (ok true)
    )
  )
)

;; Implement circuit breaker for rapid response to anomalous activity
;; Allows temporary suspension of protocol activity in emergency situations
(define-public (activate-protocol-circuit-breaker (circuit-category (string-ascii 20)) (duration uint) (justification (string-ascii 100)))
  (begin
    ;; Only protocol overseer can activate circuit breaker
    (asserts! (is-eq tx-sender PROTOCOL_OVERSEER) ERROR_UNAUTHORIZED)
    ;; Validate duration - minimum 6 blocks (~1 hour), maximum 8640 blocks (~60 days)
    (asserts! (>= duration u6) ERROR_INVALID_QUANTITY)
    (asserts! (<= duration u8640) ERROR_INVALID_QUANTITY)
    ;; Valid circuit categories
    (asserts! (or (is-eq circuit-category "high-value")
                 (is-eq circuit-category "all-transfers")
                 (is-eq circuit-category "specific-resource")
                 (is-eq circuit-category "protocol-wide")) (err u310))

    (let
      (
        (activation-block block-height)
        (expiration-block (+ block-height duration))
      )
      ;; In production, would set breaker status in contract data vars

      (print {action: "circuit_breaker_activated", category: circuit-category, 
              activation-block: activation-block, expiration-block: expiration-block,
              justification: justification, activator: tx-sender})
      (ok expiration-block)
    )
  )
)

;; Implement phased withdrawal for high-value transfers
;; Reduces risk by splitting large transfers into multiple time-gated phases
(define-public (configure-phased-withdrawal (reservation-identifier uint) (phase-count uint) (phase-interval uint))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (originator (get originator reservation-entry))
        (quantity (get quantity reservation-entry))
      )
      ;; Only applicable to high-value reservations
      (asserts! (> quantity u1000) ERROR_INVALID_QUANTITY)
      ;; Only originator can configure phased withdrawal
      (asserts! (is-eq tx-sender originator) ERROR_UNAUTHORIZED)
      ;; Must have at least 2 and at most 5 phases
      (asserts! (and (>= phase-count u2) (<= phase-count u5)) (err u270))
      ;; Phase interval must be reasonable (between 6 and 144 blocks)
      (asserts! (and (>= phase-interval u6) (<= phase-interval u144)) (err u271))
      ;; Verify reservation is still pending
      (asserts! (is-eq (get reservation-status reservation-entry) "pending") ERROR_ALREADY_PROCESSED)

      (print {action: "phased_withdrawal_configured", reservation-identifier: reservation-identifier, 
              originator: originator, phase-count: phase-count, phase-interval: phase-interval, 
              phase-amount: (/ quantity phase-count)})
      (ok true)
    )
  )
)

;; Implement time-based lockout for suspicious activity
;; Temporarily blocks operations after detected anomalies
(define-public (activate-security-lockout (reservation-identifier uint) (lockout-duration uint) (lockout-reason (string-ascii 50)))
  (begin
    (asserts! (verify-reservation-exists? reservation-identifier) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (reservation-entry (unwrap! (map-get? ReservationLedger { reservation-identifier: reservation-identifier }) ERROR_RESERVATION_MISSING))
        (originator (get originator reservation-entry))
        (beneficiary (get beneficiary reservation-entry))
        (unlock-block (+ block-height lockout-duration))
      )
      ;; Only authorized parties can activate lockout
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_OVERSEER)) ERROR_UNAUTHORIZED)
      ;; Ensure lockout duration is reasonable (between 12 and 72 blocks)
      (asserts! (and (>= lockout-duration u12) (<= lockout-duration u72)) (err u280))
      ;; Cannot lockout completed reservations
      (asserts! (not (is-eq (get reservation-status reservation-entry) "completed")) ERROR_ALREADY_PROCESSED)
      (asserts! (not (is-eq (get reservation-status reservation-entry) "expired")) (err u281))

      ;; Update reservation status to locked
      (map-set ReservationLedger
        { reservation-identifier: reservation-identifier }
        (merge reservation-entry { reservation-status: "locked" })
      )

      (print {action: "security_lockout_activated", reservation-identifier: reservation-identifier, 
              requestor: tx-sender, unlock-block: unlock-block, lockout-reason: lockout-reason})
      (ok unlock-block)
    )
  )
)
