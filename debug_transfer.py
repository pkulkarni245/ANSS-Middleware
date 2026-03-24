from main import FinanceTools
import asyncio

async def test_transfer():
    tools = FinanceTools()
    print("Directly calling tools.transfer_funds(amount=50, destination='test_account')...")
    try:
        result = tools.transfer_funds(amount=50.0, destination="test_account")
        print(f"Result: {result}")
    except Exception as e:
        import traceback
        print("Caught Exception!")
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_transfer())
