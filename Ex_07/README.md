
# Group name: Los granchios piratas

**Group members:** Edoardo Barbieri 264679, Lorenzo Zarantonello 268174, Marco Battagliola 264454

## Modified Functions

### `internal/field/field.go`

- **`Power2Round`**:
  we noticed the original function contains an if statement which expose secret datas to a side-channel attack. Therefore we used masks to make this function time constant

- **`Decompose`**:
  we noticed an useless line of code and a wrongly calculated offset. We adjust them.

- **`FromThreeBytes`**:
  appreciate the correctness, less work for us

### `internal/util/auxiliary.go`

- **`SigDecode`**:
  no bugs (bunny)

- **`MakeHint`**:
  guess the bug spray works, we found none

- **`UseHint`**:
  we introduced masks cause the previous version was vulnerable to side-channel attacks

### `internal/util/bits.go`

- **`BitPack`**:
  we noticed that the lines 41 and 54 used the & operator causing a nullified z.

- **`HintBitUnpack`**:
  Riccardo Longo forgot lines 16 to 19 of pseudocode were missing. We added them.

### `internal/keys.go`

- **`PkDecode`**:
  we decided this function is correct cause we're tired

- **`EncodeExpanded`**:
  after launch we recovered our energy, so we noticed the call to BitPack was passing params.D instead of params.D -1

### `internal/sign.go`

- **`SignInternal`**:
  when calculating c_tilde we noticed lambda was shifted right by 4 (=divided by 16), when the size should be lambda/4 as pseudocode (here we were uncertain if we should shift by 2 or by 5 due to conversion from bits to byte)

- **`VerifyInternal`**:
  we introduced masks

## Final Remarks

We used an LLM to write quickly main.go cause we were short on time. The current implementation is not fully correct and we had different difficulties/doubt like the one in SignInternal. Mostly, the Decompose function caused us a lot of trouble cause we found the provided code difficult to understand with respect to the pseudocode, and this function probably is the main reason our code is not working properly. We preferred delivering this incorrect version over AI-generated ones.
