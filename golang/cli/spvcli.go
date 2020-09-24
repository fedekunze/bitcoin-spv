package main

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	btcspv "github.com/summa-tx/bitcoin-spv/golang/btcspv"
)

var RootCmd = &cobra.Command{
	Use:     "btcspv",
	Short:   "Bitcoin SPV Proof Builder",
	Version: "0.0.1",
}

func GetCmdParseVin() *cobra.Command {
	return &cobra.Command{
		Use:     "parse-vin [vin]",
		Short:   "Parse a Bitcoin SPV Vin",
		Example: "btcspv parse-vin 0411c75317188acf700684e5bf54d21e64ce950b3d94ecb0f323cc4b8ca145dc860100000000ffffffff7761252b3ed6eb20468a29007e624976f01ebb182feb83fab07c79c6028308ac070000006a473044022047fa4bb5b1975f1fae539675653ecd7bb2698c0b110fc35658cd7b227f9b9a5402203407f59b9fa5e94dabc2c87fc65e740c281f9ed89b25db9517b92cac76d56a9a0121036d9401fba14d2e1bbe7074c6e716557f7c0c8a48e6e4bf12e5798c75afec992dffffffff33de669bb42c9e05dada07d81775b55397feeac27a05f55cd9d89a6f5e73252b010000006a473044022038f921af4da78526817aaea304b4a0f12615f29babc8da6d0e618db77e0b828f0220787efb070e00fb5a15db4d854813da78abde84317a0263b5d1cceba04aa486f10121036d9401fba14d2e1bbe7074c6e716557f7c0c8a48e6e4bf12e5798c75afec992dffffffffe72701f12466fc9f4e476d87084e05f22bb9869318d3dd9880d6624e95474ae9010000006b483045022100e15bcd9b6f968d29c2660cfb099350bec5a2f9702bf3fcf720161ca5b3ebec7f02206893cb8abe87d6994a06315a9bacbb47a4788a26e50eef922f8b942766fe2a2001210343c792123ca88b3062528b0aabaa1c428523ccaef0dc63cc67d8ddb98fd9f720ffffffff",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			bz := btcspv.DecodeIfHex(args[0])
			ParseVin(bz)
			return nil
		},
	}
}

func GetCmdParseVout() *cobra.Command {
	return &cobra.Command{
		Use:     "parse-vout [vout]",
		Short:   "Parse a Bitcoin SPV Vout",
		Example: "btcspv parse-vout 0x024db6000000000000160014455c0ea778752831d6fc25f6f8cf55dc49d335f040420f0000000000220020aedad4518f56379ef6f1f52f2e0fed64608006b3ccaff2253d847ddc90c91922",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			bz := btcspv.DecodeIfHex(args[0])
			result := ParseVout(bz)

			fmt.Println(result)
			return nil
		},
	}
}

func GetCmdParseHeader() *cobra.Command {
	return &cobra.Command{
		Use:     "parse-header [raw_header]",
		Short:   "Parse a Bitcoin SPV Header",
		Example: "btcspv parse-header 0x0000002073bd2184edd9c4fc76642ea6754ee40136970efc10c4190000000000000000000296ef123ea96da5cf695f22bf7d94be87d49db1ad7ac371ac43c4da4161c8c216349c5ba11928170d38782b",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			bz := btcspv.DecodeIfHex(args[0])
			rawHeader, err := btcspv.NewRawHeader(bz)
			if err != nil {
				return err
			}

			result := ParseHeader(rawHeader)
			fmt.Println(result)
			return nil
		},
	}
}

func GetCmdValidateHeaderChain() *cobra.Command {
	return &cobra.Command{
		Use:     "validate-header-chain [header_chain]",
		Short:   "Validate a chain of bitcoin headers",
		Example: "btcspv validate-header-chain 0x0000002073bd2184edd9c4fc76642ea6754ee40136970efc10c4190000000000000000000296ef123ea96da5cf695f22bf7d94be87d49db1ad7ac371ac43c4da4161c8c216349c5ba11928170d38782b00000020fe70e48339d6b17fbbf1340d245338f57336e97767cc240000000000000000005af53b865c27c6e9b5e5db4c3ea8e024f8329178a79ddb39f7727ea2fe6e6825d1349c5ba1192817e2d9515900000020baaea6746f4c16ccb7cd961655b636d39b5fe1519b8f15000000000000000000c63a8848a448a43c9e4402bd893f701cd11856e14cbbe026699e8fdc445b35a8d93c9c5ba1192817b945dc6c00000020f402c0b551b944665332466753f1eebb846a64ef24c71700000000000000000033fc68e070964e908d961cd11033896fa6c9b8b76f64a2db7ea928afa7e304257d3f9c5ba11928176164145d0000ff3f63d40efa46403afd71a254b54f2b495b7b0164991c2d22000000000000000000f046dc1b71560b7d0786cfbdb25ae320bd9644c98d5c7c77bf9df05cbe96212758419c5ba1192817a2bb2caa00000020e2d4f0edd5edd80bdcb880535443747c6b22b48fb6200d0000000000000000001d3799aa3eb8d18916f46bf2cf807cb89a9b1b4c56c3f2693711bf1064d9a32435429c5ba1192817752e49ae0000002022dba41dff28b337ee3463bf1ab1acf0e57443e0f7ab1d000000000000000000c3aadcc8def003ecbd1ba514592a18baddddcd3a287ccf74f584b04c5c10044e97479c5ba1192817c341f595",
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			bz := btcspv.DecodeIfHex(args[0])
			result := ValidateHeaderChain(bz)
			fmt.Println(result)
			return nil
		},
	}
}

func GetCmdProve() *cobra.Command {
	return &cobra.Command{
		Use:     "prove [version] [vin] [vout] [locktime] [root_hash] [intermediate_nodes] [index]",
		Short:   "prove the correctness of a Bitcoin SPV",
		Example: "btcspv prove 0x01000000 0x011746bd867400f3494b8f44c24b83e1aa58c4f0ff25b4a61cffeffd4bc0f9ba300000000000ffffffff 0x024897070000000000220020a4333e5612ab1a1043b25755c89b16d55184a42f81799e623e6bc39db8539c180000000000000000166a14edb1b5c2f39af0fec151732585b1049b07895211 0x00000000 0x0296ef123ea96da5cf695f22bf7d94be87d49db1ad7ac371ac43c4da4161c8c2 0xe35a0d6de94b656694589964a252957e4673a9fb1d2f8b4a92e3f0a7bb654fddb94e5a1e6d7f7f499fd1be5dd30a73bf5584bf137da5fdd77cc21aeb95b9e35788894be019284bd4fbed6dd6118ac2cb6d26bc4be4e423f55a3a48f2874d8d02a65d9c87d07de21d4dfe7b0a9f4a23cc9a58373e9e6931fefdb5afade5df54c91104048df1ee999240617984e18b6f931e2373673d0195b8c6987d7ff7650d5ce53bcec46e13ab4f2da1146a7fc621ee672f62bc22742486392d75e55e67b09960c3386a0b49e75f1723d6ab28ac9a2028a0c72866e2111d79d4817b88e17c821937847768d92837bae3832bb8e5a4ab4434b97e00a6c10182f211f592409068d6f5652400d9a3d1cc150a7fb692e874cc42d76bdafc842f2fe0f835a7c24d2d60c109b187d64571efbaa8047be85821f8e67e0e85f2f5894bc63d00c2ed9d64 281",
		Args:    cobra.ExactArgs(7),
		RunE: func(_ *cobra.Command, args []string) error {
			// convert argument to a uint
			version := btcspv.DecodeIfHex(args[0])
			vin := btcspv.DecodeIfHex(args[1])
			vout := btcspv.DecodeIfHex(args[2])
			locktime := btcspv.DecodeIfHex(args[3])
			rootHash := btcspv.DecodeIfHex(args[4])
			merkleRoot, err := btcspv.NewHash256Digest(rootHash)
			if err != nil {
				return err
			}

			intermediateNodes := btcspv.DecodeIfHex(args[5])

			idx, err := strconv.ParseUint(args[6], 10, 32)
			if err != nil {
				return err
			}

			result := Prove(version, vin, vout, locktime, merkleRoot, intermediateNodes, uint(idx))
			fmt.Println(result)
			return nil
		},
	}
}

func main() {

	RootCmd.AddCommand(
		GetCmdParseVin(),
		GetCmdParseVout(),
		GetCmdParseHeader(),
		GetCmdValidateHeaderChain(),
		GetCmdProve(),
	)
}
