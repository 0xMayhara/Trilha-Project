"""Asset transfer participants (SPEC-0007 BR-17, ADR-0008 §1).

A module whose records follow an asset registers a participant at app start. Inside the transfer
transaction, after the asset's own locks and checks, `transfer_asset` calls each participant's
`authorize(principal, asset, source, destination, finding_count)` before saving the asset and
`record(principal, asset, source, destination)` after. Any exception rolls the whole transfer back.
`assets` imports no participant, so the dependency stays one-way. This is an explicit, synchronous
call inside the transaction: not a signal, not a plug-in framework."""

_participants = []


def register(participant):
    if participant not in _participants:
        _participants.append(participant)


def participants():
    return tuple(_participants)
