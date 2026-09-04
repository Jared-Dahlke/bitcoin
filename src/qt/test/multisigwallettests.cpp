// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/multisigwallettests.h>

#include <test/util/setup_common.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <qt/clientmodel.h>
#include <qt/createmultisigwalletdialog.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/psbtoperationsdialog.h>
#include <qt/walletmodel.h>
#include <script/interpreter.h>
#include <util/check.h>
#include <util/error.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <QDialogButtonBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::DuplicateMockDatabase;
using wallet::GetMockableDatabase;
using wallet::ISMINE_NO;
using wallet::RemoveWallet;
using wallet::WALLET_FLAG_BLANK_WALLET;
using wallet::WALLET_FLAG_DESCRIPTORS;
using wallet::WALLET_FLAG_DISABLE_PRIVATE_KEYS;
using wallet::WalletContext;

namespace {

const char* COSIGNER_KEY_1{"[11111111/48h/1h/0h/2h]tpubDCZrkQoEU3845aFKUu9VQBYWZtrTwxMzcxnBwKFCYXHD6gEXvtFcxddCCLFsEwmxQaG15izcHxj48SXg1QS5FQGMBx5Ak6deXKPAL7wauBU"};
const char* COSIGNER_KEY_2{"[22222222/48h/1h/0h/2h]tpubDD3UwwHoNUF4F3Vi5PiUVTc3ji1uThuRfFyBexTSHoAcHuWW2z8qEE2YujegcLtgthr3wMp3ZauvNG9eT9xfJyxXCfNty8h6rDBYU8UU1qq"};

//! Test that the dialog assembles a valid multisig descriptor from cosigner
//! keys and that importing it via interfaces::Wallet makes the wallet derive
//! the same first receiving address the dialog displayed.
void TestCreateMultisigWallet(interfaces::Node& node)
{
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);

    CreateMultisigWalletDialog dialog{nullptr};
    auto* create_button = dialog.findChild<QDialogButtonBox*>()->button(QDialogButtonBox::Ok);

    QVERIFY(!create_button->isEnabled());
    dialog.findChild<QLineEdit*>("wallet_name_line_edit")->setText("multisig_wallet");
    dialog.findChild<QLineEdit*>("cosigner_key_edit_0")->setText(COSIGNER_KEY_1);
    dialog.findChild<QLineEdit*>("cosigner_key_edit_1")->setText(COSIGNER_KEY_2);

    QVERIFY(create_button->isEnabled());
    QCOMPARE(dialog.descriptors().size(), 2);
    for (const QString& desc : dialog.descriptors()) {
        QVERIFY(desc.startsWith("wsh(sortedmulti(2,"));
        QVERIFY(desc.contains('#')); // checksum appended
    }
    QVERIFY(dialog.firstAddress().startsWith("bcrt1"));
    const QString first_address{dialog.firstAddress()};

    // Using the same key for two cosigners must not validate.
    dialog.findChild<QLineEdit*>("cosigner_key_edit_1")->setText(COSIGNER_KEY_1);
    QVERIFY(!create_button->isEnabled());
    QVERIFY(dialog.descriptors().isEmpty());
    dialog.findChild<QLineEdit*>("cosigner_key_edit_1")->setText(COSIGNER_KEY_2);
    QVERIFY(create_button->isEnabled());

    // Import the descriptor into a watch-only wallet and check that the
    // wallet hands out the address the dialog displayed.
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);

    WalletContext& context = *node.walletLoader().context();
    AddWallet(context, wallet);
    auto wallet_interface = interfaces::MakeWallet(context, wallet);
    for (int i = 0; i < dialog.descriptors().size(); ++i) {
        const auto import_result{wallet_interface->importDescriptor(dialog.descriptors()[i].toStdString(), /*internal=*/i == 1, GetTime(), /*rescan=*/false)};
        QVERIFY(bool(import_result));
    }

    const auto dest{wallet_interface->getNewDestination(OutputType::BECH32, "")};
    QVERIFY(bool(dest));
    QCOMPARE(QString::fromStdString(EncodeDestination(*dest)), first_address);

    // Unranged descriptors cannot be imported as active.
    const auto unranged_result{wallet_interface->importDescriptor("addr(" + first_address.toStdString() + ")", /*internal=*/false, GetTime(), /*rescan=*/false)};
    QVERIFY(!unranged_result);

    // The watch-only wallet cannot produce a cosigner key...
    QVERIFY(!wallet_interface->getMultisigCosignerKey());

    // ...but a wallet with private keys can, at the BIP 48 multisig path,
    // and the dialog accepts the derived key.
    const std::shared_ptr<CWallet> signer_wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    signer_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(signer_wallet->cs_wallet);
        signer_wallet->SetupDescriptorScriptPubKeyMans();
    }
    AddWallet(context, signer_wallet);
    auto signer_interface = interfaces::MakeWallet(context, signer_wallet);
    const auto cosigner_key{signer_interface->getMultisigCosignerKey()};
    QVERIFY(bool(cosigner_key));
    QVERIFY(QString::fromStdString(*cosigner_key).contains("/48h/1h/0h/2h]tpub"));
    dialog.findChild<QLineEdit*>("cosigner_key_edit_0")->setText(QString::fromStdString(*cosigner_key));
    QVERIFY(create_button->isEnabled());

    // The signer wallet can produce the multisig descriptors with its own
    // private key substituted in, for import into a dedicated signing wallet.
    const QStringList descriptors{dialog.descriptors()};
    QCOMPARE(descriptors.size(), 2);
    const QString multisig_address{dialog.firstAddress()}; // changed with cosigner 1's key
    std::vector<std::string> priv_descs;
    for (const QString& desc : descriptors) {
        const auto priv_desc{signer_interface->getMultisigParticipationDescriptor(desc.toStdString())};
        QVERIFY(bool(priv_desc));
        QVERIFY(QString::fromStdString(*priv_desc).contains("tprv"));
        priv_descs.push_back(*priv_desc);
    }
    QVERIFY(bool(signer_interface->getMultisigCosignerKey()));

    // Importing the participation descriptors into a dedicated signing wallet
    // makes the multisig addresses IsMine there — and only there: the source
    // wallet must not recognize them, or the multisig funds would count
    // toward its balance and break its coin selection.
    const std::shared_ptr<CWallet> participation_wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    participation_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    participation_wallet->SetWalletFlag(WALLET_FLAG_BLANK_WALLET);
    AddWallet(context, participation_wallet);
    auto participation_interface = interfaces::MakeWallet(context, participation_wallet);
    for (size_t i = 0; i < priv_descs.size(); ++i) {
        QVERIFY(bool(participation_interface->importDescriptor(priv_descs[i], /*internal=*/i == 1, GetTime(), /*rescan=*/false)));
    }
    const CTxDestination multisig_dest{DecodeDestination(multisig_address.toStdString())};
    QVERIFY(IsValidDestination(multisig_dest));
    {
        LOCK(participation_wallet->cs_wallet);
        QVERIFY(participation_wallet->IsMine(multisig_dest) != ISMINE_NO);
    }
    {
        LOCK(signer_wallet->cs_wallet);
        QVERIFY(signer_wallet->IsMine(multisig_dest) == ISMINE_NO);
    }
    // The signing wallet derives the same first receiving address.
    const auto participation_dest{participation_interface->getNewDestination(OutputType::BECH32, "")};
    QVERIFY(bool(participation_dest));
    QCOMPARE(QString::fromStdString(EncodeDestination(*participation_dest)), multisig_address);

    // Reload the signing wallet from a copy of its database. The in-memory
    // Descriptor objects built at import time are discarded, so signing below
    // must rely solely on the cosigner key as persisted to disk. This mirrors
    // real usage (walletprocesspsbt / GUI Load PSBT after a restart).
    std::unique_ptr<wallet::WalletDatabase> reload_db{DuplicateMockDatabase(GetMockableDatabase(*participation_wallet))};
    RemoveWallet(context, participation_wallet, /*load_on_start=*/std::nullopt);
    bilingual_str reload_error;
    std::vector<bilingual_str> reload_warnings;
    const std::shared_ptr<CWallet> reloaded_wallet{CWallet::Create(context, "", std::move(reload_db), WALLET_FLAG_DESCRIPTORS, reload_error, reload_warnings)};
    QVERIFY(reloaded_wallet != nullptr);
    AddWallet(context, reloaded_wallet);
    {
        LOCK(reloaded_wallet->cs_wallet);
        QVERIFY(reloaded_wallet->IsMine(multisig_dest) != ISMINE_NO);
    }

    // The reloaded signer wallet can now add its signature to a PSBT spending
    // the multisig, e.g. one created by the watch-only multisig wallet.
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(COIN, GetScriptForDestination(multisig_dest));
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0));
    spend_tx.vout.emplace_back(COIN - 10000, GetScriptForDestination(multisig_dest));
    PartiallySignedTransaction psbtx{spend_tx};
    psbtx.inputs[0].witness_utxo = funding_tx.vout[0];
    bool complete{true};
    QVERIFY(reloaded_wallet->FillPSBT(psbtx, complete, SIGHASH_ALL, /*sign=*/true, /*bip32derivs=*/true) == TransactionError::OK);
    QVERIFY(!complete); // the other cosigner's signature is still missing
    QCOMPARE(psbtx.inputs[0].partial_sigs.size(), size_t{1});

    // The PSBT dialog reports the cosigner's partial signature as progress,
    // not as a failure to sign.
    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    OptionsModel options_model{node};
    bilingual_str options_error;
    QVERIFY(options_model.Init(options_error));
    ClientModel client_model{node, &options_model};
    WalletModel wallet_model{interfaces::MakeWallet(context, reloaded_wallet), client_model, platform_style.get()};
    PSBTOperationsDialog psbt_dialog{nullptr, &wallet_model, &client_model};
    PartiallySignedTransaction gui_psbtx{spend_tx};
    gui_psbtx.inputs[0].witness_utxo = funding_tx.vout[0];
    psbt_dialog.openWithPSBT(gui_psbtx);
    auto* sign_button = psbt_dialog.findChild<QPushButton*>("signTransactionButton");
    QVERIFY(sign_button->isEnabled());
    sign_button->click();
    QCOMPARE(psbt_dialog.findChild<QLabel*>("statusBar")->text(),
             QString{"Added signature(s) to 1 input(s). More signatures are still required."});

    // A wallet whose key is not part of the descriptor cannot participate.
    const std::shared_ptr<CWallet> other_wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    other_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(other_wallet->cs_wallet);
        other_wallet->SetupDescriptorScriptPubKeyMans();
    }
    AddWallet(context, other_wallet);
    auto other_interface = interfaces::MakeWallet(context, other_wallet);
    QVERIFY(!other_interface->getMultisigParticipationDescriptor(descriptors[0].toStdString()));

    RemoveWallet(context, other_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, reloaded_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, signer_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

} // namespace

void MultisigWalletTests::multisigWalletTests()
{
    TestCreateMultisigWallet(m_node);
}
