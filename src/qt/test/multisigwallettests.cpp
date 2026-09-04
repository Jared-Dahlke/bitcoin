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
#include <qt/walletcontroller.h>
#include <qt/walletmodel.h>
#include <util/check.h>
#include <validation.h>
#include <util/time.h>
#include <util/translation.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <QApplication>
#include <QDebug>
#include <QEventLoop>
#include <QDialogButtonBox>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTimer>

#include <algorithm>

using wallet::AddWallet;
using wallet::CWallet;
using wallet::CreateMockableWalletDatabase;
using wallet::GetWallet;
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
    const auto import_result{wallet_interface->importDescriptor(dialog.descriptor().toStdString(), GetTime(), /*rescan=*/false)};
    QVERIFY(bool(import_result));

    const auto dest{wallet_interface->getNewDestination(OutputType::BECH32, "")};
    QVERIFY(bool(dest));
    QCOMPARE(QString::fromStdString(EncodeDestination(*dest)), first_address);

    // Unranged descriptors cannot be imported as active.
    const auto unranged_result{wallet_interface->importDescriptor("addr(" + first_address.toStdString() + ")", GetTime(), /*rescan=*/false)};
    QVERIFY(!unranged_result);

    // The watch-only wallet cannot produce a cosigner key...
    QVERIFY(!wallet_interface->getMultisigCosignerKey());

    // ...but a wallet with private keys can, at the BIP 48 multisig path,
    // and the dialog accepts the derived key. Create the signer wallet
    // through the loader, so it lives on disk and can be reloaded below.
    std::vector<bilingual_str> signer_warnings;
    auto signer_result{node.walletLoader().createWallet("signer", /*passphrase=*/{}, WALLET_FLAG_DESCRIPTORS, signer_warnings)};
    QVERIFY(bool(signer_result));
    std::unique_ptr<interfaces::Wallet> signer_interface{std::move(*signer_result)};
    const auto cosigner_key{signer_interface->getMultisigCosignerKey()};
    QVERIFY(bool(cosigner_key));
    QVERIFY(QString::fromStdString(*cosigner_key).contains("/48h/1h/0h/2h]tpub"));
    dialog.findChild<QLineEdit*>("cosigner_key_edit_0")->setText(QString::fromStdString(*cosigner_key));
    QVERIFY(create_button->isEnabled());

    // The signer wallet learns to sign for the multisig via a non-active
    // helper descriptor covering its cosigner key's child keys.
    const QString descriptor{dialog.descriptor()};
    QVERIFY(!descriptor.isEmpty());
    const QString multisig_address{dialog.firstAddress()}; // changed with cosigner 1's key
    qDebug() << "checkpoint: importMultisigSigningKey";
    QVERIFY(bool(signer_interface->importMultisigSigningKey(descriptor.toStdString())));
    // Repeating the import is a no-op, not an error.
    QVERIFY(bool(signer_interface->importMultisigSigningKey(descriptor.toStdString())));
    const CTxDestination multisig_dest{DecodeDestination(multisig_address.toStdString())};
    QVERIFY(IsValidDestination(multisig_dest));
    // The helper must not make the wallet treat the multisig funds as its
    // own: they would count toward its balance and break its coin selection.
    {
        const std::shared_ptr<CWallet> signer_wallet{GetWallet(context, "signer")};
        QVERIFY(signer_wallet != nullptr);
        LOCK(signer_wallet->cs_wallet);
        QVERIFY(!signer_wallet->IsMine(multisig_dest));
    }
    // Deriving the cosigner key still works.
    QVERIFY(bool(signer_interface->getMultisigCosignerKey()));

    // A second watch-only wallet tracks this multisig (the first one tracks
    // the descriptor built before cosigner 1's key was replaced) and
    // prepares its PSBTs.
    qDebug() << "checkpoint: watch wallet import";
    const std::shared_ptr<CWallet> watch_wallet = std::make_shared<CWallet>(node.context()->chain.get(), "", CreateMockableWalletDatabase());
    watch_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    watch_wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    AddWallet(context, watch_wallet);
    auto watch_interface = interfaces::MakeWallet(context, watch_wallet);
    QVERIFY(bool(watch_interface->importDescriptor(descriptor.toStdString(), GetTime(), /*rescan=*/false)));

    // Unload the signer wallet and reload it from disk. The in-memory
    // Descriptor objects built at import time are discarded, so signing
    // below must rely solely on the helper as persisted to disk. This
    // mirrors real usage (walletprocesspsbt / GUI Load PSBT after a
    // restart).
    qDebug() << "checkpoint: reload";
    signer_interface->remove();
    signer_interface.reset();
    std::vector<bilingual_str> load_warnings;
    auto reload_result{node.walletLoader().loadWallet("signer", load_warnings)};
    QVERIFY(bool(reload_result));
    const std::shared_ptr<CWallet> reloaded_wallet{GetWallet(context, "signer")};
    QVERIFY(reloaded_wallet != nullptr);

    // The watch-only wallet prepares a PSBT spending the multisig, filling
    // in the witness script and key origins that let cosigner wallets sign.
    qDebug() << "checkpoint: prepare PSBT";
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(COIN, GetScriptForDestination(multisig_dest));
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0));
    spend_tx.vout.emplace_back(COIN - 10000, GetScriptForDestination(multisig_dest));
    PartiallySignedTransaction psbtx{spend_tx};
    psbtx.inputs[0].witness_utxo = funding_tx.vout[0];
    bool complete{true};
    QVERIFY(!watch_interface->fillPSBT({.sign = false, .bip32_derivs = true}, /*n_signed=*/nullptr, psbtx, complete));
    QVERIFY(!complete);
    QVERIFY(!psbtx.inputs[0].witness_script.empty()); // multisig details ride in the PSBT
    QVERIFY(!psbtx.inputs[0].hd_keypaths.empty());

    // The reloaded signer wallet adds its signature purely from the PSBT
    // metadata — it never imported the multisig descriptor itself.
    qDebug() << "checkpoint: sign PSBT";
    QVERIFY(!reloaded_wallet->FillPSBT(psbtx, {.sign = true, .bip32_derivs = true}, complete));
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
    QVERIFY(!watch_interface->fillPSBT({.sign = false, .bip32_derivs = true}, /*n_signed=*/nullptr, gui_psbtx, complete));
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
    QVERIFY(!other_interface->importMultisigSigningKey(descriptor.toStdString()));

    RemoveWallet(context, other_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, reloaded_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, watch_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}


//! Drive the full Create Multisig Wallet activity like a user would: fill in
//! the real dialog (cosigner 1 through the "From wallet" menu), accept it,
//! and verify that the watch-only wallet is created on disk, that the source
//! wallet learns to sign for the multisig without treating its funds as its
//! own, and that it adds a partial signature to a PSBT prepared by the
//! created wallet.
void TestCreateMultisigWalletActivity(interfaces::Node& node)
{
#ifdef Q_OS_MACOS
    if (QApplication::platformName() == "minimal") {
        // Disable for mac on "minimal" platform to avoid hangs inside the Qt
        // framework when modal dialogs are shown
        // (https://bugreports.qt.io/browse/QTBUG-49686).
        qWarning() << "Skipping TestCreateMultisigWalletActivity on mac build with 'minimal' platform set due to Qt bugs. "
                      "Invoke with 'QT_QPA_PLATFORM=cocoa test_bitcoin-qt' on mac, or else use a linux or windows build.";
        return;
    }
#endif
    TestChain100Setup test;
    auto wallet_loader = interfaces::MakeWalletLoader(*test.m_node.chain, *Assert(test.m_node.args));
    test.m_node.wallet_loader = wallet_loader.get();
    node.setContext(&test.m_node);
    WalletContext& context = *node.walletLoader().context();

    std::unique_ptr<const PlatformStyle> platform_style{PlatformStyle::instantiate("other")};
    OptionsModel options_model{node};
    bilingual_str options_error;
    QVERIFY(options_model.Init(options_error));
    ClientModel client_model{node, &options_model};
    WalletController controller{client_model, platform_style.get(), nullptr};

    // A loaded wallet with private keys serves as cosigner 1.
    const std::shared_ptr<CWallet> source_wallet = std::make_shared<CWallet>(node.context()->chain.get(), "source", CreateMockableWalletDatabase());
    source_wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    {
        LOCK(source_wallet->cs_wallet);
        source_wallet->SetupDescriptorScriptPubKeyMans();
        // The wallet model requires a processed block height.
        source_wallet->SetLastBlockProcessed(100, WITH_LOCK(node.context()->chainman->GetMutex(), return node.context()->chainman->ActiveChain().Tip()->GetBlockHash()));
    }
    AddWallet(context, source_wallet);
    WalletModel* source_model{controller.getOrCreateWallet(interfaces::MakeWallet(context, source_wallet))};
    QVERIFY(source_model);

    auto* activity = new CreateMultisigWalletActivity(&controller, /*parent_widget=*/nullptr);
    QPointer<CreateMultisigWalletActivity> activity_guard{activity};
    WalletModel* created_model{nullptr};
    QObject::connect(activity, &CreateMultisigWalletActivity::created, [&](WalletModel* model) { created_model = model; });
    QEventLoop loop;
    QObject::connect(activity, &CreateMultisigWalletActivity::finished, &loop, &QEventLoop::quit);
    activity->create();

    CreateMultisigWalletDialog* activity_dialog{nullptr};
    for (QWidget* widget : QApplication::topLevelWidgets()) {
        if (auto* d{qobject_cast<CreateMultisigWalletDialog*>(widget)}) activity_dialog = d;
    }
    QVERIFY(activity_dialog);
    activity_dialog->findChild<QLineEdit*>("wallet_name_line_edit")->setText("msig_e2e");
    // Fill cosigner 1 through the real "From wallet" menu, so the activity
    // records the source wallet for the signing-key import.
    QPushButton* from_wallet_button{nullptr};
    for (auto* button : activity_dialog->findChildren<QPushButton*>()) {
        if (button->menu()) {
            from_wallet_button = button;
            break;
        }
    }
    QVERIFY(from_wallet_button);
    from_wallet_button->menu()->actions().first()->trigger();
    QVERIFY(activity_dialog->cosignerKey(0).contains("tpub"));
    activity_dialog->findChild<QLineEdit*>("cosigner_key_edit_1")->setText(COSIGNER_KEY_2);
    const QString multisig_address{activity_dialog->firstAddress()};
    QVERIFY(!multisig_address.isEmpty());

    // Dismiss message boxes (e.g. "Multisig wallet created") as they appear,
    // recording their contents.
    QTimer dismiss_timer;
    QStringList shown_messages;
    QObject::connect(&dismiss_timer, &QTimer::timeout, [&] {
        if (auto* box{qobject_cast<QMessageBox*>(QApplication::activeModalWidget())}) {
            shown_messages << box->text();
            box->button(QMessageBox::Ok)->click();
        }
    });
    dismiss_timer.start(std::chrono::milliseconds{100});
    QTimer::singleShot(std::chrono::seconds{60}, &loop, &QEventLoop::quit); // safety timeout
    activity_dialog->accept();
    loop.exec();
    dismiss_timer.stop();

    QVERIFY(created_model != nullptr);
    QCOMPARE(QString::fromStdString(created_model->wallet().getWalletName()), QString{"msig_e2e"});
    QVERIFY(created_model->wallet().privateKeysDisabled());
    // The created watch-only wallet hands out the address the dialog showed.
    const auto dest{created_model->wallet().getNewDestination(OutputType::BECH32, "")};
    QVERIFY(bool(dest));
    QCOMPARE(QString::fromStdString(EncodeDestination(*dest)), multisig_address);
    // The user was told which wallets can sign for the multisig.
    QVERIFY(std::any_of(shown_messages.begin(), shown_messages.end(), [](const QString& m) { return m.contains("can sign for the multisig"); }));

    // The source wallet learned to sign, but does not treat the multisig
    // funds as its own.
    const CTxDestination multisig_dest{DecodeDestination(multisig_address.toStdString())};
    QVERIFY(IsValidDestination(multisig_dest));
    {
        LOCK(source_wallet->cs_wallet);
        QVERIFY(!source_wallet->IsMine(multisig_dest));
    }
    CMutableTransaction funding_tx;
    funding_tx.vout.emplace_back(COIN, GetScriptForDestination(multisig_dest));
    CMutableTransaction spend_tx;
    spend_tx.vin.emplace_back(COutPoint(funding_tx.GetHash(), 0));
    spend_tx.vout.emplace_back(COIN - 10000, GetScriptForDestination(multisig_dest));
    PartiallySignedTransaction psbtx{spend_tx};
    psbtx.inputs[0].witness_utxo = funding_tx.vout[0];
    bool complete{true};
    QVERIFY(!created_model->wallet().fillPSBT({.sign = false, .bip32_derivs = true}, /*n_signed=*/nullptr, psbtx, complete));
    QVERIFY(!psbtx.inputs[0].witness_script.empty());
    QVERIFY(!source_wallet->FillPSBT(psbtx, {.sign = true, .bip32_derivs = true}, complete));
    QVERIFY(!complete); // the other cosigner's signature is still missing
    QCOMPARE(psbtx.inputs[0].partial_sigs.size(), size_t{1});

    if (activity_guard) delete activity;
    const std::shared_ptr<CWallet> created_wallet{GetWallet(context, "msig_e2e")};
    QVERIFY(created_wallet != nullptr);
    RemoveWallet(context, created_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, source_wallet, /*load_on_start=*/std::nullopt);
}

} // namespace

void MultisigWalletTests::multisigWalletTests()
{
    TestCreateMultisigWallet(m_node);
    TestCreateMultisigWalletActivity(m_node);
}
