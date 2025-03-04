// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package v2

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/algorand/go-codec/codec"
	"github.com/labstack/echo/v4"

	"github.com/algorand/go-algorand/daemon/algod/api/server/v2/generated/model"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/ledger/simulation"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/protocol"
)

// returnError logs an internal message while returning the encoded response.
func returnError(ctx echo.Context, code int, internal error, external string, logger logging.Logger) error {
	logger.Info(internal)
	return ctx.JSON(code, model.ErrorResponse{Message: external})
}

func badRequest(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusBadRequest, internal, external, log)
}

func serviceUnavailable(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusServiceUnavailable, internal, external, log)
}

func timeout(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusRequestTimeout, internal, external, log)
}

func internalError(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusInternalServerError, internal, external, log)
}

func notFound(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusNotFound, internal, external, log)
}

func notImplemented(ctx echo.Context, internal error, external string, log logging.Logger) error {
	return returnError(ctx, http.StatusNotImplemented, internal, external, log)
}

func addrOrNil(addr basics.Address) *string {
	if addr.IsZero() {
		return nil
	}
	ret := addr.String()
	return &ret
}

func strOrNil(str string) *string {
	if str == "" {
		return nil
	}
	return &str
}

func numOrNil(num uint64) *uint64 {
	if num == 0 {
		return nil
	}
	return &num
}

func byteOrNil(data []byte) *[]byte {
	if len(data) == 0 {
		return nil
	}
	return &data
}

func trueOrNil(b bool) *bool {
	if !b {
		return nil
	}
	return &b
}

func nilToZero(numPtr *uint64) uint64 {
	if numPtr == nil {
		return 0
	}
	return *numPtr
}

func computeCreatableIndexInPayset(tx node.TxnWithStatus, txnCounter uint64, payset []transactions.SignedTxnWithAD) (cidx *uint64) {
	// Compute transaction index in block
	offset := -1
	for idx, stxnib := range payset {
		if tx.Txn.Txn.ID() == stxnib.Txn.ID() {
			offset = idx
			break
		}
	}

	// Sanity check that txn was in fetched block
	if offset < 0 {
		return nil
	}

	// Count into block to get created asset index
	idx := txnCounter - uint64(len(payset)) + uint64(offset) + 1
	return &idx
}

// computeAssetIndexFromTxn returns the created asset index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAssetIndexFromTxn(tx node.TxnWithStatus, l LedgerForAPI) *uint64 {
	// Must have ledger
	if l == nil {
		return nil
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return nil
	}
	// Transaction must be AssetConfig transaction
	if tx.Txn.Txn.AssetConfigTxnFields == (transactions.AssetConfigTxnFields{}) {
		return nil
	}
	// Transaction must be creating an asset
	if tx.Txn.Txn.AssetConfigTxnFields.ConfigAsset != 0 {
		return nil
	}

	aid := uint64(tx.ApplyData.ConfigAsset)
	if aid > 0 {
		return &aid
	}
	// If there is no ConfigAsset in the ApplyData, it must be a
	// transaction before inner transactions were activated. Therefore
	// the computeCreatableIndexInPayset function will work properly
	// to deduce the aid. Proceed.

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return nil
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil
	}

	return computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

// computeAppIndexFromTxn returns the created app index given a confirmed
// transaction whose confirmation block is available in the ledger. Note that
// 0 is an invalid asset index (they start at 1).
func computeAppIndexFromTxn(tx node.TxnWithStatus, l LedgerForAPI) *uint64 {
	// Must have ledger
	if l == nil {
		return nil
	}
	// Transaction must be confirmed
	if tx.ConfirmedRound == 0 {
		return nil
	}
	// Transaction must be ApplicationCall transaction
	if tx.Txn.Txn.ApplicationCallTxnFields.Empty() {
		return nil
	}
	// Transaction must be creating an application
	if tx.Txn.Txn.ApplicationCallTxnFields.ApplicationID != 0 {
		return nil
	}

	aid := uint64(tx.ApplyData.ApplicationID)
	if aid > 0 {
		return &aid
	}
	// If there is no ApplicationID in the ApplyData, it must be a
	// transaction before inner transactions were activated. Therefore
	// the computeCreatableIndexInPayset function will work properly
	// to deduce the aid. Proceed.

	// Look up block where transaction was confirmed
	blk, err := l.Block(tx.ConfirmedRound)
	if err != nil {
		return nil
	}

	payset, err := blk.DecodePaysetFlat()
	if err != nil {
		return nil
	}

	return computeCreatableIndexInPayset(tx, blk.BlockHeader.TxnCounter, payset)
}

// getCodecHandle converts a format string into the encoder + content type
func getCodecHandle(formatPtr *string) (codec.Handle, string, error) {
	format := "json"
	if formatPtr != nil {
		format = strings.ToLower(*formatPtr)
	}

	switch format {
	case "json":
		return protocol.JSONStrictHandle, "application/json", nil
	case "msgpack":
		fallthrough
	case "msgp":
		return protocol.CodecHandle, "application/msgpack", nil
	default:
		return nil, "", fmt.Errorf("invalid format: %s", format)
	}
}

func encode(handle codec.Handle, obj interface{}) ([]byte, error) {
	var output []byte
	enc := codec.NewEncoderBytes(&output, handle)

	err := enc.Encode(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to encode object: %v", err)
	}
	return output, nil
}

func decode(handle codec.Handle, data []byte, v interface{}) error {
	enc := codec.NewDecoderBytes(data, handle)

	err := enc.Decode(v)
	if err != nil {
		return fmt.Errorf("failed to decode object: %v", err)
	}
	return nil
}

// Helper to convert basics.StateDelta -> *model.StateDelta
func stateDeltaToStateDelta(d basics.StateDelta) *model.StateDelta {
	if len(d) == 0 {
		return nil
	}
	var delta model.StateDelta
	for k, v := range d {
		delta = append(delta, model.EvalDeltaKeyValue{
			Key: base64.StdEncoding.EncodeToString([]byte(k)),
			Value: model.EvalDelta{
				Action: uint64(v.Action),
				Bytes:  strOrNil(base64.StdEncoding.EncodeToString([]byte(v.Bytes))),
				Uint:   numOrNil(v.Uint),
			},
		})
	}
	return &delta
}

func edIndexToAddress(index uint64, txn *transactions.Transaction, shared []basics.Address) string {
	// index into [Sender, txn.Accounts[0], txn.Accounts[1], ..., shared[0], shared[1], ...]
	switch {
	case index == 0:
		return txn.Sender.String()
	case int(index-1) < len(txn.Accounts):
		return txn.Accounts[index-1].String()
	case int(index-1)-len(txn.Accounts) < len(shared):
		return shared[int(index-1)-len(txn.Accounts)].String()
	default:
		return fmt.Sprintf("Invalid Account Index %d in LocalDelta", index)
	}
}

func convertToDeltas(txn node.TxnWithStatus) (*[]model.AccountStateDelta, *model.StateDelta) {
	var localStateDelta *[]model.AccountStateDelta
	if len(txn.ApplyData.EvalDelta.LocalDeltas) > 0 {
		d := make([]model.AccountStateDelta, 0)
		shared := txn.ApplyData.EvalDelta.SharedAccts

		for k, v := range txn.ApplyData.EvalDelta.LocalDeltas {
			d = append(d, model.AccountStateDelta{
				Address: edIndexToAddress(k, &txn.Txn.Txn, shared),
				Delta:   *(stateDeltaToStateDelta(v)),
			})
		}

		localStateDelta = &d
	}

	return localStateDelta, stateDeltaToStateDelta(txn.ApplyData.EvalDelta.GlobalDelta)
}

func convertLogs(txn node.TxnWithStatus) *[][]byte {
	var logItems *[][]byte
	if len(txn.ApplyData.EvalDelta.Logs) > 0 {
		l := make([][]byte, len(txn.ApplyData.EvalDelta.Logs))

		for i, log := range txn.ApplyData.EvalDelta.Logs {
			l[i] = []byte(log)
		}

		logItems = &l
	}
	return logItems
}

func convertInners(txn *node.TxnWithStatus) *[]PreEncodedTxInfo {
	inner := make([]PreEncodedTxInfo, len(txn.ApplyData.EvalDelta.InnerTxns))
	for i := range txn.ApplyData.EvalDelta.InnerTxns {
		inner[i] = ConvertInnerTxn(&txn.ApplyData.EvalDelta.InnerTxns[i])
	}
	return &inner
}

// ConvertInnerTxn converts an inner SignedTxnWithAD to PreEncodedTxInfo for the REST API
func ConvertInnerTxn(txn *transactions.SignedTxnWithAD) PreEncodedTxInfo {
	// This copies from handlers.PendingTransactionInformation, with
	// simplifications because we have a SignedTxnWithAD rather than
	// TxnWithStatus, and we know this txn has committed.

	response := PreEncodedTxInfo{Txn: txn.SignedTxn}

	response.ClosingAmount = &txn.ApplyData.ClosingAmount.Raw
	response.AssetClosingAmount = &txn.ApplyData.AssetClosingAmount
	response.SenderRewards = &txn.ApplyData.SenderRewards.Raw
	response.ReceiverRewards = &txn.ApplyData.ReceiverRewards.Raw
	response.CloseRewards = &txn.ApplyData.CloseRewards.Raw

	// Since this is an inner txn, we know these indexes will be populated. No
	// need to search payset for IDs
	response.AssetIndex = numOrNil(uint64(txn.ApplyData.ConfigAsset))
	response.ApplicationIndex = numOrNil(uint64(txn.ApplyData.ApplicationID))

	withStatus := node.TxnWithStatus{
		Txn:       txn.SignedTxn,
		ApplyData: txn.ApplyData,
	}
	response.LocalStateDelta, response.GlobalStateDelta = convertToDeltas(withStatus)
	response.Logs = convertLogs(withStatus)
	response.Inners = convertInners(&withStatus)
	return response
}

func convertTxnResult(txnResult simulation.TxnResult) PreEncodedSimulateTxnResult {
	return PreEncodedSimulateTxnResult{
		Txn:                    ConvertInnerTxn(&txnResult.Txn),
		AppBudgetConsumed:      numOrNil(txnResult.AppBudgetConsumed),
		LogicSigBudgetConsumed: numOrNil(txnResult.LogicSigBudgetConsumed),
	}
}

func convertTxnGroupResult(txnGroupResult simulation.TxnGroupResult) PreEncodedSimulateTxnGroupResult {
	txnResults := make([]PreEncodedSimulateTxnResult, len(txnGroupResult.Txns))
	for i, txnResult := range txnGroupResult.Txns {
		txnResults[i] = convertTxnResult(txnResult)
	}

	encoded := PreEncodedSimulateTxnGroupResult{
		Txns:              txnResults,
		FailureMessage:    strOrNil(txnGroupResult.FailureMessage),
		AppBudgetAdded:    numOrNil(txnGroupResult.AppBudgetAdded),
		AppBudgetConsumed: numOrNil(txnGroupResult.AppBudgetConsumed),
	}

	if len(txnGroupResult.FailedAt) > 0 {
		failedAt := make([]uint64, len(txnGroupResult.FailedAt))
		copy(failedAt, txnGroupResult.FailedAt)
		encoded.FailedAt = &failedAt
	}

	return encoded
}

func convertSimulationResult(result simulation.Result) PreEncodedSimulateResponse {
	var evalOverrides *model.SimulationEvalOverrides
	if result.EvalOverrides != (simulation.ResultEvalOverrides{}) {
		evalOverrides = &model.SimulationEvalOverrides{
			AllowEmptySignatures: trueOrNil(result.EvalOverrides.AllowEmptySignatures),
			MaxLogSize:           result.EvalOverrides.MaxLogSize,
			MaxLogCalls:          result.EvalOverrides.MaxLogCalls,
			ExtraOpcodeBudget:    numOrNil(result.EvalOverrides.ExtraOpcodeBudget),
		}
	}

	encodedSimulationResult := PreEncodedSimulateResponse{
		Version:       result.Version,
		LastRound:     uint64(result.LastRound),
		TxnGroups:     make([]PreEncodedSimulateTxnGroupResult, len(result.TxnGroups)),
		EvalOverrides: evalOverrides,
	}

	for i, txnGroup := range result.TxnGroups {
		encodedSimulationResult.TxnGroups[i] = convertTxnGroupResult(txnGroup)
	}

	return encodedSimulationResult
}

func convertSimulationRequest(request PreEncodedSimulateRequest) simulation.Request {
	txnGroups := make([][]transactions.SignedTxn, len(request.TxnGroups))
	for i, txnGroup := range request.TxnGroups {
		txnGroups[i] = txnGroup.Txns
	}
	return simulation.Request{
		TxnGroups:            txnGroups,
		AllowEmptySignatures: request.AllowEmptySignatures,
		AllowMoreLogging:     request.AllowMoreLogging,
		ExtraOpcodeBudget:    request.ExtraOpcodeBudget,
	}
}

// printableUTF8OrEmpty checks to see if the entire string is a UTF8 printable string.
// If this is the case, the string is returned as is. Otherwise, the empty string is returned.
func printableUTF8OrEmpty(in string) string {
	// iterate throughout all the characters in the string to see if they are all printable.
	// when range iterating on go strings, go decode each element as a utf8 rune.
	for _, c := range in {
		// is this a printable character, or invalid rune ?
		if c == utf8.RuneError || !unicode.IsPrint(c) {
			return ""
		}
	}
	return in
}
