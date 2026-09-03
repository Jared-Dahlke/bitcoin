// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/test/multisigwallettests.h>

#include <test/util/setup_common.h>

#include <interfaces/node.h>
#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>
#include <qt/createmultisigwalletdialog.h>
#include <util/check.h>
#include <util/time.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <QDialogButtonBox>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::RemoveWallet;
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
    QVERIFY(dialog.descriptor().startsWith("wsh(sortedmulti(2,"));
    QVERIFY(dialog.descriptor().contains('#')); // checksum appended
    QVERIFY(dialog.firstAddress().startsWith("bcrt1"));
    const QString first_address{dialog.firstAddress()};

    // Using the same key for two cosigners must not validate.
    dialog.findChild<QLineEdit*>("cosigner_key_edit_1")->setText(COSIGNER_KEY_1);
    QVERIFY(!create_button->isEnabled());
    QVERIFY(dialog.descriptor().isEmpty());
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
    const auto import_result{wallet_interface->importDescriptor(dialog.descriptor().toStdString(), GetTime())};
    QVERIFY(bool(import_result));

    const auto dest{wallet_interface->getNewDestination(OutputType::BECH32, "")};
    QVERIFY(bool(dest));
    QCOMPARE(QString::fromStdString(EncodeDestination(*dest)), first_address);

    // Unranged descriptors cannot be imported as active.
    const auto unranged_result{wallet_interface->importDescriptor("addr(" + first_address.toStdString() + ")", GetTime())};
    QVERIFY(!unranged_result);

    // The watch-only wallet cannot produce a cosigner key...
    QVERIFY(!wallet_interface->getMultisigCosignerKey());

    // ...but a wallet with private keys can, at the BIP 87 multisig path,
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

    RemoveWallet(context, signer_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

} // namespace

void MultisigWalletTests::multisigWalletTests()
{
    TestCreateMultisigWallet(m_node);
}
